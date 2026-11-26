<?php

namespace BWH\AuthManager\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * Notices that the database was restored from a backup before the operator has said so.
 *
 * Every authentication event appends to the audit log, so its highest id only ever grows. This
 * records the highest id seen, with the recovery epoch it was seen under, in a small file outside
 * the database. A database behind that file was rolled back: credential generations, grants and
 * disables made since the backup are gone, and a consumer asking whether a person is still active
 * would be told what was true then. Identity status refuses to answer, with a retryable 503,
 * until the operator raises the recovery epoch (docs/recovery.md), which starts a new record. The
 * refusal is recorded in the file, so it holds even once new sign-ins carry the restored log back
 * past the mark.
 *
 * It costs one indexed MAX(id) and one locked read of a few bytes per status request, plus a
 * write when the log has grown. A configured epoch below the recorded one, or a file that cannot
 * be read or written, also refuses: either is a sign the instance is not what it was.
 */
final class RecoveryHighWater
{
    public function epoch(): int
    {
        return (int) config('auth-manager.recovery.epoch', 1);
    }

    /** Whether identity status may be answered: the database is not behind what this instance saw. */
    public function current(): bool
    {
        if (! (bool) config('auth-manager.recovery.high_water_guard', true)) {
            return true;
        }

        try {
            // Read under the file lock, so concurrent requests compare in the order they record:
            // a maximum read before another request recorded a larger one is never compared with it.
            $highest = static fn (): int => (int) DB::table((string) config('bherila-auth.audit.table', 'auth_audit_log'))->max('id');

            return $this->record((string) config('auth-manager.recovery.high_water_path'), $this->epoch(), $highest);
        } catch (Throwable $failure) {
            Log::error('The recovery high-water record could not be checked; identity status is refused.', ['exception' => $failure::class]);

            return false;
        }
    }

    /** @param  \Closure(): int  $highest  the audit log's highest id, read once the record is locked */
    private function record(string $path, int $epoch, \Closure $highest): bool
    {
        $directory = dirname($path);
        if (! is_dir($directory) && ! @mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new RuntimeException('The high-water directory cannot be created.');
        }
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            throw new RuntimeException('The high-water file cannot be opened.');
        }

        try {
            if (! flock($handle, LOCK_EX)) {
                throw new RuntimeException('The high-water file cannot be locked.');
            }
            $recorded = $this->read((string) stream_get_contents($handle));
            $seen = $highest();
            if ($recorded !== null && $recorded['epoch'] > $epoch) {
                Log::warning('The configured recovery epoch is below the recorded one; identity status is refused.', ['configured' => $epoch, 'recorded' => $recorded['epoch']]);

                return false;
            }
            if ($recorded !== null && $recorded['epoch'] === $epoch) {
                if ($recorded['rolled_back']) {
                    // Once seen, a rollback stays declared until the operator raises the epoch, however
                    // far new sign-ins carry the restored log past the mark again.
                    return false;
                }
                if ($seen < $recorded['high_water']) {
                    Log::warning('The database is behind the recovery high-water mark; identity status is refused until the recovery epoch is raised.', ['seen' => $seen, 'high_water' => $recorded['high_water'], 'epoch' => $epoch]);
                    $this->write($handle, ['epoch' => $epoch, 'high_water' => $recorded['high_water'], 'rolled_back' => true]);

                    return false;
                }
                if ($seen === $recorded['high_water']) {
                    return true;
                }
            }

            // A first record, a newly raised epoch, or a log that has grown.
            $this->write($handle, ['epoch' => $epoch, 'high_water' => $seen]);

            return true;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * @param  resource  $handle  the locked record
     * @param  array{epoch: int, high_water: int, rolled_back?: true}  $record
     */
    private function write($handle, array $record): void
    {
        $bytes = json_encode($record, JSON_THROW_ON_ERROR);
        if (! ftruncate($handle, 0) || ! rewind($handle) || fwrite($handle, $bytes) !== strlen($bytes) || ! fflush($handle)) {
            throw new RuntimeException('The high-water file cannot be written.');
        }
        if (function_exists('fsync')) {
            fsync($handle);
        }
    }

    /**
     * A record written before rollbacks were kept has no `rolled_back` key and reads as none seen.
     *
     * @return array{epoch: int, high_water: int, rolled_back: bool}|null
     */
    private function read(string $contents): ?array
    {
        if ($contents === '') {
            return null;
        }
        try {
            $recorded = json_decode($contents, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException('The high-water file is not valid JSON.');
        }
        if (! is_array($recorded)
            || ! in_array(array_keys($recorded), [['epoch', 'high_water'], ['epoch', 'high_water', 'rolled_back']], true)
            || ! is_int($recorded['epoch']) || $recorded['epoch'] < 1
            || ! is_int($recorded['high_water']) || $recorded['high_water'] < 0
            || (array_key_exists('rolled_back', $recorded) && $recorded['rolled_back'] !== true)) {
            throw new RuntimeException('The high-water file is malformed.');
        }

        return ['epoch' => $recorded['epoch'], 'high_water' => $recorded['high_water'], 'rolled_back' => array_key_exists('rolled_back', $recorded)];
    }
}
