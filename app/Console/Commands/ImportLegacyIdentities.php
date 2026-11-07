<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Console\Command;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;
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

    /** @var array<int, true> */
    private array $sourceTestLoginIds = [];

    public function handle(): int
    {
        $this->presentUserIds = [];
        $this->sourceTestLoginIds = [];
        $only = $this->option('only');

        if ($only !== null && ! in_array($only, ['users', 'passkeys'], true)) {
            $this->error('--only accepts "users" or "passkeys".');

            return self::FAILURE;
        }

        try {
            $legacy = $this->legacyConnection();
        } catch (Throwable) {
            $this->error('The configured legacy identity source cannot be reached safely.');

            return self::FAILURE;
        }

        try {
            $userColumnMap = $only === null || $only === 'users'
                ? $this->legacyUserColumnMap($legacy)
                : null;
            $hasLegacyPasskeys = $only === null || $only === 'passkeys'
                ? $this->hasSupportedLegacyPasskeys($legacy)
                : false;
            if ($legacy->getSchemaBuilder()->hasColumns('users', ['id', 'is_test_login'])) {
                $this->sourceTestLoginIds = array_fill_keys($legacy->table('users')->where('is_test_login', true)
                    ->pluck('id')->map(static fn (mixed $id): int => (int) $id)->all(), true);
            }
        } catch (QueryException) {
            $this->error('The configured legacy identity source cannot be reached safely.');

            return self::FAILURE;
        } catch (Throwable) {
            $this->error('The legacy identity source has an unsupported schema. Nothing was written.');

            return self::FAILURE;
        }

        $apply = (bool) $this->option('apply');

        if (! $apply) {
            $this->warn('Dry run. Nothing will be written. Pass --apply to commit.');
        }

        $summary = [];

        if ($only === null || $only === 'users') {
            $summary['users'] = $this->importUsers($legacy, $apply, $userColumnMap);
        }

        if ($only === null || $only === 'passkeys') {
            $summary['passkeys'] = $this->importPasskeys($legacy, $apply, $hasLegacyPasskeys);
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

        // Establish the connection before schema preflight so authentication and
        // network failures are reported as source availability problems.
        $connection->getPdo();

        return $connection;
    }

    /**
     * @param  array{name:string,role:string,last_login:string,role_is_admin:bool}  $columnMap
     * @return array{created:int,updated:int,unchanged:int,skipped:int}
     */
    private function importUsers(ConnectionInterface $legacy, bool $apply, array $columnMap): array
    {
        $counts = ['created' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0];

        $rows = $legacy->table('users')
            ->select([
                'id',
                "{$columnMap['name']} as name",
                'email',
                'email_verified_at',
                'password',
                "{$columnMap['role']} as user_role",
                'remember_token',
                "{$columnMap['last_login']} as last_login_date",
                'created_at',
                'updated_at',
            ])
            ->orderBy('id')
            ->get();

        foreach ($rows as $row) {
            if (isset($this->sourceTestLoginIds[(int) $row->id])) {
                $this->warn('A legacy user record was skipped because the source subject is a managed test login.');
                $counts['skipped']++;

                continue;
            }
            if (! is_string($row->email) || trim($row->email) === '') {
                $this->warn('A legacy user record was skipped because it has no usable email address.');
                $counts['skipped']++;

                continue;
            }

            if (! is_string($row->password) || trim($row->password) === '') {
                $this->warn('A legacy user record was skipped because it has no usable password credential.');
                $counts['skipped']++;

                continue;
            }

            // Identifiers are preserved deliberately. The OAuth subject claim is the user
            // key, and relying applications have already bound their local records to it;
            // reassigning identifiers here would silently detach every one of them.
            if (DB::table('identity_tombstones')->where('subject', $row->id)->exists()) {
                $this->warn('A legacy user record was skipped because it has a provider deletion tombstone.');
                $counts['skipped']++;

                continue;
            }

            $existing = DB::table('users')->where('id', $row->id)->first();
            if ((bool) ($existing->is_test_login ?? false)) {
                $this->warn('A legacy user record was skipped because the subject is a managed test login.');
                $counts['skipped']++;

                continue;
            }
            $role = $columnMap['role_is_admin']
                ? $this->roleFromAdminFlag($row->user_role)
                : (string) $row->user_role;

            $attributes = [
                'name' => $row->name,
                'email' => $row->email,
                'email_verified_at' => $row->email_verified_at,
                'password' => $row->password,
                'user_role' => $role,
                'remember_token' => $row->remember_token,
                'last_login_date' => $row->last_login_date,
                'created_at' => $row->created_at,
                'updated_at' => $row->updated_at,
            ];
            // After initial creation, provider roles belong to this directory.
            // Replaying a legacy snapshot must never demote its recovery admin.
            if ($existing !== null) {
                $attributes['user_role'] = $existing->user_role;
                $attributes['remember_token'] = $existing->remember_token;
            }

            $collision = DB::table('users')
                ->where('email', $row->email)
                ->where('id', '!=', $row->id)
                ->exists();

            if ($collision) {
                $this->warn('A legacy user record was skipped because its address belongs to another account.');
                $counts['skipped']++;

                continue;
            }

            if ($existing === null) {
                if ($apply) {
                    DB::transaction(function () use ($row, $attributes, $role): void {
                        DB::table('users')->insert(['id' => $row->id] + $attributes);

                        if ($this->roleMaySignIn($role)) {
                            $this->grantCurrentClients((int) $row->id);
                        }
                    });
                }
                $this->presentUserIds[(int) $row->id] = true;
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
                $updated = DB::transaction(function () use ($row, $attributes): bool {
                    $users = app(ProviderAdministrators::class)->lockDirectory();
                    $locked = $users->first(static fn ($user): bool => (int) $user->id === (int) $row->id);
                    if ($locked === null || $locked->trashed() || $locked->isTestLogin()
                        || DB::table('identity_tombstones')->where('subject', $row->id)->exists()) {
                        return false;
                    }
                    // Re-read under the same lock as HTTP and operator role changes.
                    $attributes['user_role'] = $locked->user_role;
                    $credentialChanged = ! hash_equals((string) $locked->password, (string) $attributes['password']);
                    // A legacy replay must not revive a remember cookie revoked by
                    // a later provider-administrator or credential change.
                    $attributes['remember_token'] = $locked->remember_token;
                    DB::table('users')->where('id', $row->id)->update($attributes);
                    if ($credentialChanged) {
                        app(ProviderAdministrators::class)->invalidateAuthority($locked->refresh());
                    }

                    return true;
                }, 3);
                if (! $updated) {
                    $counts['skipped']++;

                    continue;
                }
            }
            $counts['updated']++;
        }

        return $counts;
    }

    /**
     * Only explicitly supported source schemas may be imported. This prevents a
     * partially matching database from being mistaken for the legacy source.
     *
     * @return array{name:string,role:string,last_login:string,role_is_admin:bool}
     */
    private function legacyUserColumnMap(ConnectionInterface $legacy): array
    {
        $schema = $legacy->getSchemaBuilder();

        if (! $schema->hasTable('users')) {
            throw new \RuntimeException('Legacy users table is missing.');
        }

        $common = [
            'id',
            'email',
            'email_verified_at',
            'password',
            'remember_token',
            'created_at',
            'updated_at',
        ];

        if ($schema->hasColumns('users', [...$common, 'name', 'user_role', 'last_login_date'])) {
            return [
                'name' => 'name',
                'role' => 'user_role',
                'last_login' => 'last_login_date',
                'role_is_admin' => false,
            ];
        }

        if ($schema->hasColumns('users', [...$common, 'alias', 'is_admin', 'last_login_at'])) {
            return [
                'name' => 'alias',
                'role' => 'is_admin',
                'last_login' => 'last_login_at',
                'role_is_admin' => true,
            ];
        }

        throw new \RuntimeException('Legacy users table has an unsupported schema.');
    }

    private function roleFromAdminFlag(mixed $value): string
    {
        return in_array($value, [true, 1, '1'], true) ? 'admin' : 'user';
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
        return ! isset($this->sourceTestLoginIds[$userId])
            && ! DB::table('users')->where('id', $userId)->where('is_test_login', true)->exists()
            && ! DB::table('identity_tombstones')->where('subject', $userId)->exists()
            && (isset($this->presentUserIds[$userId])
                || DB::table('users')->where('id', $userId)->exists());
    }

    /**
     * @return array{created:int,updated:int,unchanged:int,skipped:int}
     */
    private function importPasskeys(ConnectionInterface $legacy, bool $apply, bool $hasLegacyPasskeys): array
    {
        $counts = ['created' => 0, 'updated' => 0, 'unchanged' => 0, 'skipped' => 0];

        if (! $hasLegacyPasskeys) {
            $this->warn('The legacy source has no passkey table; skipping passkeys.');

            return $counts;
        }

        $rows = $legacy->table('webauthn_credentials')->orderBy('id')->get();

        foreach ($rows as $row) {
            if (! $this->userWillExist((int) $row->user_id)) {
                $managed = isset($this->sourceTestLoginIds[(int) $row->user_id])
                    || DB::table('users')->where('id', $row->user_id)->where('is_test_login', true)->exists();
                $this->warn($managed
                    ? 'A legacy passkey record was skipped because its owner is a managed test login.'
                    : 'A legacy passkey record was skipped because its owner is not present.');
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
            $counts['updated']++;
        }

        return $counts;
    }

    private function hasSupportedLegacyPasskeys(ConnectionInterface $legacy): bool
    {
        $schema = $legacy->getSchemaBuilder();

        if (! $schema->hasTable('webauthn_credentials')) {
            return false;
        }

        if (! $schema->hasColumns('webauthn_credentials', [
            'id',
            'user_id',
            'credential_id',
            'credential_id_hash',
            'public_key',
            'counter',
            'aaguid',
            'name',
            'transports',
            'last_used_at',
            'created_at',
            'updated_at',
        ])) {
            throw new \RuntimeException('Legacy passkey table has an unsupported schema.');
        }

        return true;
    }
}
