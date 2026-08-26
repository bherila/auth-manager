<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * One-time, repeatable import of identities from the application that previously owned them.
 *
 * Reports what it would do and changes nothing unless --apply is passed, so the plan can be
 * read before it is trusted. It never deletes and never demotes: rows absent from the source
 * are left alone, because this service becomes authoritative the moment it is cut over and a
 * later re-run must not undo changes made here.
 */
class ImportLegacyIdentities extends Command
{
    protected $signature = 'identity:import-legacy
        {--apply : Write the changes. Without this the command only reports what it would do.}
        {--only= : Restrict to one stage: users or passkeys.}';

    protected $description = 'Import identities from the legacy source database.';

    /**
     * Identifiers that exist, or would exist once this run is applied.
     *
     * A dry run writes nothing, so a later stage checking the database directly would
     * report every dependent row as an orphan and describe an outcome that will not
     * happen. Tracking intent separately keeps the dry-run report truthful.
     *
     * @var array<int, true>
     */
    private array $presentUserIds = [];

    public function handle(): int
    {
        $only = $this->option('only');

        if ($only !== null && ! in_array($only, ['users', 'passkeys'], true)) {
            $this->error('--only accepts "users" or "passkeys".');

            return self::FAILURE;
        }

        try {
            $legacy = $this->legacyConnection();
        } catch (Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $apply = (bool) $this->option('apply');

        if (! $apply) {
            $this->warn('Dry run. Nothing will be written. Pass --apply to commit.');
        }

        $summary = [];

        if ($only === null || $only === 'users') {
            $summary['users'] = $this->importUsers($legacy, $apply);
        }

        if ($only === null || $only === 'passkeys') {
            $summary['passkeys'] = $this->importPasskeys($legacy, $apply);
        }

        $this->newLine();
        foreach ($summary as $stage => $counts) {
            $this->line(sprintf(
                '%-9s created %d, updated %d, unchanged %d, skipped %d',
                $stage,
                $counts['created'],
                $counts['updated'],
                $counts['unchanged'],
                $counts['skipped'],
            ));
        }

        return self::SUCCESS;
    }

    /**
     * The source must be named explicitly. An unconfigured source is an error, never a
     * silent fall-through to this service's own database, which would read as an empty
     * source and report a successful no-op import.
     */
    private function legacyConnection(): ConnectionInterface
    {
        $database = config('database.connections.legacy_identity.database');

        if (! is_string($database) || $database === '') {
            throw new \RuntimeException(
                'The legacy_identity connection is not configured. Set LEGACY_IDENTITY_DB_* before importing.'
            );
        }

        $connection = DB::connection('legacy_identity');

        $default = config('database.default');

        if ($database === config("database.connections.{$default}.database")) {
            throw new \RuntimeException('The legacy source and this service point at the same database.');
        }

        return $connection;
    }

    /**
     * @return array{created:int,updated:int,unchanged:int,skipped:int}
     */
    private function importUsers(ConnectionInterface $legacy, bool $apply): array
    {
        $counts = ['created' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0];

        $rows = $legacy->table('users')
            ->select('id', 'name', 'email', 'email_verified_at', 'password', 'user_role', 'remember_token', 'last_login_date', 'created_at', 'updated_at')
            ->orderBy('id')
            ->get();

        foreach ($rows as $row) {
            // Identifiers are preserved deliberately. The OAuth subject claim is the user
            // key, and relying applications have already bound their local records to it;
            // reassigning identifiers here would silently detach every one of them.
            $existing = DB::table('users')->where('id', $row->id)->first();

            $attributes = [
                'name' => $row->name,
                'email' => $row->email,
                'email_verified_at' => $row->email_verified_at,
                'password' => $row->password,
                'user_role' => $row->user_role,
                'remember_token' => $row->remember_token,
                'last_login_date' => $row->last_login_date,
                'created_at' => $row->created_at,
                'updated_at' => $row->updated_at,
            ];

            $collision = DB::table('users')
                ->where('email', $row->email)
                ->where('id', '!=', $row->id)
                ->exists();

            if ($collision) {
                $this->warn(sprintf('users#%d skipped: its address is already held by a different identifier.', $row->id));
                $counts['skipped']++;

                continue;
            }

            if ($existing === null) {
                if ($apply) {
                    DB::transaction(function () use ($row, $attributes): void {
                        DB::table('users')->insert(['id' => $row->id] + $attributes);

                        if ($this->roleMaySignIn((string) $row->user_role)) {
                            $this->grantCurrentClients((int) $row->id);
                        }
                    });
                }
                $this->presentUserIds[(int) $row->id] = true;
                $this->line(sprintf('  create users#%d', $row->id));
                $counts['created']++;

                continue;
            }

            $this->presentUserIds[(int) $row->id] = true;

            $differs = array_filter(
                $attributes,
                static fn (mixed $value, string $key): bool => ($existing->{$key} ?? null) != $value,
                ARRAY_FILTER_USE_BOTH,
            );

            if ($differs === []) {
                $counts['unchanged']++;

                continue;
            }

            if ($apply) {
                DB::table('users')->where('id', $row->id)->update($attributes);
            }
            $this->line(sprintf('  update users#%d (%s)', $row->id, implode(', ', array_keys($differs))));
            $counts['updated']++;
        }

        return $counts;
    }

    private function roleMaySignIn(string $role): bool
    {
        $roles = array_filter(array_map(
            static fn (string $value): string => strtolower(trim($value)),
            explode(',', $role),
        ));

        return in_array('user', $roles, true) || in_array('admin', $roles, true);
    }

    private function grantCurrentClients(int $subject): void
    {
        $now = now();
        $grants = DB::table('oauth_clients')
            ->where('revoked', false)
            ->pluck('id')
            ->map(static fn (mixed $clientId): array => [
                'oauth_client_id' => (string) $clientId,
                'subject' => $subject,
                'created_at' => $now,
                'updated_at' => $now,
            ])
            ->all();

        if ($grants !== []) {
            DB::table('oauth_client_grants')->insert($grants);
        }
    }

    private function userWillExist(int $userId): bool
    {
        return isset($this->presentUserIds[$userId])
            || DB::table('users')->where('id', $userId)->exists();
    }

    /**
     * @return array{created:int,updated:int,unchanged:int,skipped:int}
     */
    private function importPasskeys(ConnectionInterface $legacy, bool $apply): array
    {
        $counts = ['created' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0];

        $rows = $legacy->table('webauthn_credentials')->orderBy('id')->get();

        foreach ($rows as $row) {
            if (! $this->userWillExist((int) $row->user_id)) {
                $this->warn(sprintf('passkey#%d skipped: its owner users#%d is not present.', $row->id, $row->user_id));
                $counts['skipped']++;

                continue;
            }

            // Matched on the credential itself rather than the row identifier: the
            // authenticator's credential ID is the stable identity of a passkey.
            $existing = DB::table('webauthn_credentials')
                ->where('credential_id', $row->credential_id)
                ->first();

            $attributes = [
                'user_id' => $row->user_id,
                'credential_id' => $row->credential_id,
                'credential_id_hash' => $row->credential_id_hash,
                'public_key' => $row->public_key,
                'counter' => $row->counter,
                'aaguid' => $row->aaguid,
                'name' => $row->name,
                'transports' => $row->transports,
                'last_used_at' => $row->last_used_at,
                'created_at' => $row->created_at,
                'updated_at' => $row->updated_at,
            ];

            if ($existing === null) {
                if ($apply) {
                    DB::table('webauthn_credentials')->insert($attributes);
                }
                $this->line(sprintf('  create passkey for users#%d (%s)', $row->user_id, $row->name));
                $counts['created']++;

                continue;
            }

            // The signature counter only ever moves forward. Never lower it: a lower
            // stored counter defeats the clone detection it exists to provide.
            if ((int) $existing->counter > (int) $row->counter) {
                $attributes['counter'] = $existing->counter;
            }

            $differs = array_filter(
                $attributes,
                static fn (mixed $value, string $key): bool => ($existing->{$key} ?? null) != $value,
                ARRAY_FILTER_USE_BOTH,
            );

            if ($differs === []) {
                $counts['unchanged']++;

                continue;
            }

            if ($apply) {
                DB::table('webauthn_credentials')->where('id', $existing->id)->update($attributes);
            }
            $this->line(sprintf('  update passkey#%d (%s)', $existing->id, implode(', ', array_keys($differs))));
            $counts['updated']++;
        }

        return $counts;
    }
}
