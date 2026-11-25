<?php

namespace BWH\AuthManager\Services;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use JsonException;
use RuntimeException;

/**
 * Copies new authentication audit rows to storage a database restore cannot roll back.
 *
 * Each run writes the rows after the last exported one as new, immutable objects named
 * `<prefix>/<yyyy>/<mm>/<dd>/e<epoch>-<first id>-<last id>.jsonl.gz` and never overwrites or
 * deletes one. Where to start is read from the destination itself, the newest object's name and
 * its last row, falling back to a small local state file; never from the database, so a restored
 * database can neither make it export a row twice nor skip one. Before exporting it checks that
 * the database still holds the last exported row: a database that does not was rolled back, and
 * the run refuses until the operator raises the recovery epoch (docs/recovery.md). Under a newly
 * raised epoch it starts after the newest row the previous epoch's export already holds, so rows
 * written since the restore, which reuse ids the export has seen, are exported and nothing
 * restored is copied again.
 *
 * Rows carry no address, network address, browser string or session id: the address and the
 * session id are hashed and the rest left out, and metadata keys that could hold a credential are
 * redacted, because the copy cannot be changed once written.
 */
final class OffboxAuditExport
{
    /** Rows younger than this are left for the next run: an earlier id may still be uncommitted. */
    public const SETTLE_SECONDS = 60;

    private const NAME = '/^e([1-9]\d*)-([1-9]\d*)-([1-9]\d*)\.jsonl\.gz$/';

    private const SENSITIVE_KEY = '/password|secret|token|cookie|assertion|private|passcode|otp|(^|_)code$/i';

    /** @return array{objects: list<string>, rows: int} */
    public function export(int $maxObjects): array
    {
        $disk = $this->disk();
        $start = $this->start($this->newest($disk));
        $written = [];
        $rows = 0;

        while (count($written) < $maxObjects) {
            $batch = $this->settledRowsAfter($start);
            if ($batch === []) {
                break;
            }
            $first = $batch[0]['id'];
            $last = $batch[array_key_last($batch)];
            $path = sprintf('%s/%s/e%d-%d-%d.jsonl.gz', $this->prefix(), Carbon::now('UTC')->format('Y/m/d'), $this->epoch(), $first, $last['id']);
            if ($disk->exists($path)) {
                throw new OffboxAuditExportRefused("An export object already exists at {$path}; it is never overwritten. Nothing further was exported.");
            }
            $lines = implode('', array_map(static fn (array $row): string => json_encode($row, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)."\n", $batch));
            $bytes = gzencode($lines, 9);
            if ($bytes === false || $disk->put($path, $bytes) !== true) {
                throw new RuntimeException('The export object could not be written.');
            }
            $this->writeState($this->entry($this->epoch(), $last, $path));
            $written[] = $path;
            $rows += count($batch);
            $start = $last['id'];
            if (count($batch) < $this->batchSize()) {
                break;
            }
        }

        return ['objects' => $written, 'rows' => $rows];
    }

    /**
     * Where the export stands, without writing anything.
     *
     * @return array{newest: string|null, epoch: int|null, last_id: int|null, database_max_id: int, pending: int, oldest_pending: string|null}
     */
    public function status(): array
    {
        $disk = $this->disk();
        $newest = $this->newest($disk);
        $start = $this->start($newest);
        $pending = $this->table()->where('id', '>', $start);

        return [
            'newest' => $newest['object'] ?? null,
            'epoch' => $newest['epoch'] ?? null,
            'last_id' => $newest['id'] ?? null,
            'database_max_id' => (int) $this->table()->max('id'),
            'pending' => (clone $pending)->count(),
            'oldest_pending' => ($oldest = (clone $pending)->orderBy('id')->value('created_at')) === null ? null : (string) $oldest,
        ];
    }

    public function configuredDisk(): ?string
    {
        $disk = config('auth-manager.recovery.audit_export.disk');

        return is_string($disk) && $disk !== '' ? $disk : null;
    }

    private function disk(): Filesystem
    {
        $name = $this->configuredDisk();
        if ($name === null) {
            throw new OffboxAuditExportRefused('AUTH_MANAGER_AUDIT_EXPORT_DISK is not set, so there is no off-box audit copy. Name a filesystem disk for it (docs/recovery.md). Nothing was exported.');
        }

        return Storage::disk($name);
    }

    /**
     * The id to export after: the last exported row when the database still holds it, otherwise,
     * under a newly raised epoch, the newest restored row the export already holds.
     *
     * @param  array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string}|null  $newest
     */
    private function start(?array $newest): int
    {
        if ($newest === null) {
            return 0;
        }
        $epoch = $this->epoch();
        if ($epoch < $newest['epoch']) {
            throw new OffboxAuditExportRefused("The configured recovery epoch ({$epoch}) is below the newest exported one ({$newest['epoch']}). Nothing was exported.");
        }
        $row = $this->table()->where('id', $newest['id'])->first();
        if ($row !== null && $this->fingerprint($this->row($row)) === $this->fingerprint($newest)) {
            return $newest['id'];
        }
        if ($epoch === $newest['epoch']) {
            throw new OffboxAuditExportRefused("The database no longer holds the last exported audit row (id {$newest['id']}): it was restored or rolled back. Raise AUTH_MANAGER_RECOVERY_EPOCH (docs/recovery.md). Nothing was exported and no object was changed.");
        }
        if ($newest['created_at'] === null) {
            throw new OffboxAuditExportRefused('The newest export object has no timestamp to resume from. Nothing was exported.');
        }

        // Everything the restored database holds up to the last exported row's time was
        // exported before the restore; rows written since then are newer than it.
        return (int) $this->table()->where('created_at', '<=', $newest['created_at'])->max('id');
    }

    /**
     * The newest exported row: from the newest object in the destination, or the local state
     * when the state is further on (the destination listing missed it) or the destination is
     * empty (every object expired).
     *
     * @return array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string}|null
     */
    private function newest(Filesystem $disk): ?array
    {
        $found = $this->newestInDestination($disk);
        $state = $this->readState();
        if ($state === null) {
            return $found;
        }
        if ($found === null || [$state['epoch'], $state['id']] > [$found['epoch'], $found['id']]) {
            return $state;
        }

        return $found;
    }

    /** @return array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string}|null */
    private function newestInDestination(Filesystem $disk): ?array
    {
        foreach ($this->descending($disk, $this->prefix(), '/^\d{4}$/') as $year) {
            foreach ($this->descending($disk, $year, '/^\d{2}$/') as $month) {
                foreach ($this->descending($disk, $month, '/^\d{2}$/') as $day) {
                    $best = null;
                    foreach ($disk->files($day) as $file) {
                        if (preg_match(self::NAME, basename($file), $name) === 1
                            && ($best === null || [(int) $name[1], (int) $name[3]] > [$best[0], $best[1]])) {
                            $best = [(int) $name[1], (int) $name[3], $file];
                        }
                    }
                    if ($best !== null) {
                        return $this->lastRowOf($disk, $best[2], $best[0], $best[1]);
                    }
                }
            }
        }

        return null;
    }

    /** @return list<string> */
    private function descending(Filesystem $disk, string $directory, string $pattern): array
    {
        $found = array_values(array_filter($disk->directories($directory), static fn (string $path): bool => preg_match($pattern, basename($path)) === 1));
        usort($found, static fn (string $a, string $b): int => strcmp(basename($b), basename($a)));

        return $found;
    }

    /** @return array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string} */
    private function lastRowOf(Filesystem $disk, string $path, int $epoch, int $id): array
    {
        $bytes = $disk->get($path);
        $lines = is_string($bytes) ? @gzdecode($bytes) : false;
        $rows = $lines === false ? [] : array_values(array_filter(explode("\n", $lines), static fn (string $line): bool => $line !== ''));
        try {
            $last = $rows === [] ? null : json_decode($rows[array_key_last($rows)], true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $last = null;
        }
        if (! is_array($last) || ($last['id'] ?? null) !== $id || ! is_string($last['event'] ?? null)) {
            throw new OffboxAuditExportRefused("The newest export object ({$path}) cannot be read back, so where to resume is unknown. Nothing was exported.");
        }

        return $this->entry($epoch, $last, $path);
    }

    /**
     * Rows after the given id, oldest first, up to the batch size, stopping at the first one too
     * recent to be sure every earlier id is committed.
     *
     * @return list<array<string, mixed>>
     */
    private function settledRowsAfter(int $id): array
    {
        $cutoff = Carbon::now()->subSeconds(self::SETTLE_SECONDS);
        $rows = [];
        foreach ($this->table()->where('id', '>', $id)->orderBy('id')->limit($this->batchSize())->get() as $row) {
            if ($row->created_at !== null && Carbon::parse((string) $row->created_at)->greaterThan($cutoff)) {
                break;
            }
            $rows[] = $this->row($row);
        }

        return $rows;
    }

    /** @return array<string, mixed> */
    private function row(object $row): array
    {
        $metadata = is_string($row->metadata ?? null) ? json_decode($row->metadata, true) : null;

        return [
            'id' => (int) $row->id,
            'created_at' => $row->created_at === null ? null : (string) $row->created_at,
            'event' => (string) $row->event,
            'succeeded' => (bool) $row->succeeded,
            'auth_method' => $row->auth_method === null ? null : (string) $row->auth_method,
            'reason' => $row->reason === null ? null : (string) $row->reason,
            'user_id' => $row->user_id === null ? null : (int) $row->user_id,
            'acting_user_id' => $row->acting_user_id === null ? null : (int) $row->acting_user_id,
            // The same normalization the sign-in throttles key on; the address itself is never copied.
            'email_sha256' => is_string($row->email) && $row->email !== '' ? hash('sha256', mb_strtolower(trim($row->email))) : null,
            'session_sha256' => is_string($row->session_id) && $row->session_id !== '' ? hash('sha256', $row->session_id) : null,
            'is_suspicious' => (bool) $row->is_suspicious,
            'metadata' => is_array($metadata) ? $this->redact($metadata) : null,
        ];
    }

    /**
     * @param  array<mixed>  $metadata
     * @return array<mixed>
     */
    private function redact(array $metadata): array
    {
        foreach ($metadata as $key => $value) {
            if (is_string($key) && preg_match(self::SENSITIVE_KEY, $key) === 1) {
                $metadata[$key] = '[redacted]';
            } elseif (is_array($value)) {
                $metadata[$key] = $this->redact($value);
            }
        }

        return $metadata;
    }

    /** @param array<string, mixed> $row */
    private function fingerprint(array $row): string
    {
        return json_encode([$row['id'], $row['created_at'], $row['event'], $row['user_id']], JSON_THROW_ON_ERROR);
    }

    /**
     * @param  array<string, mixed>  $row
     * @return array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string}
     */
    private function entry(int $epoch, array $row, string $object): array
    {
        return [
            'epoch' => $epoch,
            'id' => (int) $row['id'],
            'created_at' => is_string($row['created_at'] ?? null) ? $row['created_at'] : null,
            'event' => (string) $row['event'],
            'user_id' => is_int($row['user_id'] ?? null) ? $row['user_id'] : null,
            'object' => $object,
        ];
    }

    /** @return array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string}|null */
    private function readState(): ?array
    {
        $path = $this->statePath();
        if (! is_file($path)) {
            return null;
        }
        try {
            $state = json_decode((string) file_get_contents($path), true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new OffboxAuditExportRefused('The audit export state file is not valid JSON. Nothing was exported.');
        }
        if (! is_array($state) || ($state['disk'] ?? null) !== $this->configuredDisk() || ($state['prefix'] ?? null) !== $this->prefix()) {
            // A record of a different destination says nothing about this one.
            return null;
        }
        if (! is_int($state['epoch'] ?? null) || $state['epoch'] < 1 || ! is_int($state['id'] ?? null) || $state['id'] < 1
            || ! is_string($state['event'] ?? null) || ! is_string($state['object'] ?? null)) {
            throw new OffboxAuditExportRefused('The audit export state file is malformed. Nothing was exported.');
        }

        return $this->entry($state['epoch'], $state, $state['object']);
    }

    /** @param array{epoch: int, id: int, created_at: string|null, event: string, user_id: int|null, object: string} $entry */
    private function writeState(array $entry): void
    {
        $path = $this->statePath();
        $directory = dirname($path);
        if (! is_dir($directory) && ! @mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('The audit export state directory cannot be created.');
        }
        $temporary = $path.'.'.bin2hex(random_bytes(6)).'.tmp';
        $bytes = json_encode(['disk' => $this->configuredDisk(), 'prefix' => $this->prefix(), ...$entry], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        if (@file_put_contents($temporary, $bytes) !== strlen($bytes) || ! @chmod($temporary, 0600) || ! @rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('The audit export state file cannot be written.');
        }
    }

    private function table(): Builder
    {
        return DB::table((string) config('bherila-auth.audit.table', 'auth_audit_log'));
    }

    private function epoch(): int
    {
        return (int) config('auth-manager.recovery.epoch', 1);
    }

    private function prefix(): string
    {
        return (string) config('auth-manager.recovery.audit_export.prefix', 'audit');
    }

    private function batchSize(): int
    {
        return max(1, (int) config('auth-manager.recovery.audit_export.batch_size', 5000));
    }

    private function statePath(): string
    {
        return (string) config('auth-manager.recovery.audit_export.state_path');
    }
}
