<?php

namespace BWH\AuthManager\Services\DirectoryCopy;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\IdentityCopy\TableSequence;
use BWH\AuthManager\Support\Mount;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use InvalidArgumentException;

/** A whole-directory move, separate from the stable selected-person identity-copy contract. */
final class DirectoryTransfer
{
    /** No session, live OAuth credential, recovery token or APP_KEY material is included. */
    public const COLUMNS = [
        'users' => ['id', 'name', 'email', 'email_verified_at', 'password', 'user_role', 'last_login_date', 'disabled_at', 'credential_version', 'deleted_at', 'created_at', 'updated_at'],
        'oauth_clients' => ['id', 'owner_type', 'owner_id', 'name', 'secret', 'provider', 'redirect_uris', 'grant_types', 'revoked', 'dynamically_registered_at', 'last_used_at', 'scopes', 'created_at', 'updated_at'],
        'passkeys' => ['id', 'user_id', 'credential_id', 'credential_id_hash', 'public_key', 'counter', 'aaguid', 'name', 'transports', 'last_used_at', 'rp_id', 'backup_eligible', 'created_at', 'updated_at'],
        'oauth_client_grants' => ['oauth_client_id', 'subject', 'created_at', 'updated_at'],
        'registered_applications' => ['id', 'key', 'name', 'launch_url', 'enabled', 'created_at', 'updated_at'],
        'registered_application_clients' => ['id', 'registered_application_id', 'oauth_client_id'],
        'access_invitations' => ['id', 'application', 'email', 'email_normalized', 'token_hash', 'pending_key', 'inviter_id', 'inviter_credential_version', 'access', 'expires_at', 'last_sent_at', 'link_handed_over', 'send_count', 'revoked_at', 'revoked_by', 'accepted_at', 'accepted_user_id', 'roles_status', 'roles_outcome', 'roles_request_id', 'roles_operation_id', 'roles_checked_at', 'requesting_client_id', 'created_at', 'updated_at'],
        'identity_tombstones' => ['id', 'public_id', 'subject', 'tombstoned_at', 'purge_after', 'provider_purged_at', 'purge_reason', 'unacknowledged_clients', 'created_at', 'updated_at'],
        'identity_tombstone_clients' => ['id', 'identity_tombstone_id', 'oauth_client_id', 'oauth_client_name', 'acknowledged_at', 'created_at', 'updated_at'],
    ];

    /** @return array<string, mixed> */
    public function snapshot(): array
    {
        $db = $this->connection();
        $sequence = new TableSequence($db);
        if (! $sequence->supported()) {
            throw new InvalidArgumentException('Directory copy supports SQLite, MySQL and MariaDB only.');
        }

        return $db->transaction(function () use ($db, $sequence): array {
            $tables = [];
            $floors = [];
            foreach (self::COLUMNS as $name => $columns) {
                $table = $this->table($name);
                $this->assertColumns($db, $table, $columns);
                $query = $db->table($table);
                foreach (in_array('id', $columns, true) ? ['id'] : ['oauth_client_id', 'subject'] as $order) {
                    $query->orderBy($order);
                }
                $rows = $query->get($columns)->map(static fn (object $row): array => (array) $row)->all();
                if ($name === 'oauth_clients') {
                    $rows = array_map(fn (array $row): array => $this->normalizeClient($row, false), $rows);
                }
                if ($name === 'users') {
                    foreach ($rows as &$row) {
                        if ((password_get_info((string) $row['password'])['algoName'] ?? 'unknown') === 'unknown') {
                            // Unknown legacy material could even be plaintext. Carry only
                            // the need for recovery, never an unrecognized credential value.
                            $row['password'] = null;
                        }
                    }
                    unset($row);
                }
                if (in_array('id', $columns, true) && $name !== 'oauth_clients') {
                    $floors[$name] = $sequence->next($table);
                }
                $tables[$name] = array_map(DirectoryArchive::packRow(...), $rows);
            }
            $floors['users'] = max($floors['users'], (int) $db->table('identity_tombstones')->max('subject') + 1);

            return [
                'source_issuer' => (string) config('auth-manager.issuer'),
                'source_rp_id' => $this->effectiveRpId(),
                'assurance' => [
                    'code_after_password' => (bool) config('auth-manager.sign_in.code_after_password'),
                    'code_only' => (bool) config('auth-manager.sign_in.code_only'),
                    'trusted_devices' => (bool) config('auth-manager.sign_in.trusted_devices'),
                    'passkey_user_verification' => (string) config('bherila-auth.passkeys.user_verification', 'preferred'),
                ],
                'sequence_floors' => $floors,
                'tables' => $tables,
            ];
        });
    }

    /** @param array<string, mixed> $payload @return array<string, int> */
    public function import(string $checksum, array $payload, bool $apply, bool $skipIncompatiblePasskeys = false, bool $resetIncompatiblePasswords = false): array
    {
        $db = $this->connection();
        $receipt = $db->table('directory_imports')->where('checksum', $checksum)->first();
        if ($receipt !== null) {
            $report = json_decode($receipt->report, true, 32, JSON_THROW_ON_ERROR);
            $report['already_imported'] = 1;

            return $report;
        }
        $tables = $this->validated($payload, $db);
        $incompatible = 0;
        $targetRp = $this->effectiveRpId();
        $targetHost = trim(strtolower((string) parse_url((string) config('app.url'), PHP_URL_HOST)), '[]');
        $rpHost = strtolower($targetRp);
        $isIp = filter_var($targetHost, FILTER_VALIDATE_IP) !== false || filter_var($rpHost, FILTER_VALIDATE_IP) !== false;
        $rpIsWithinTargetOrigin = $rpHost !== '' && ($targetHost === $rpHost || (! $isIp && str_ends_with($targetHost, '.'.$rpHost)));
        foreach ($tables['passkeys'] as $index => $row) {
            $rp = $row['rp_id'] ?? $payload['source_rp_id'];
            if (! $rpIsWithinTargetOrigin || $rp !== $targetRp || $payload['source_rp_id'] !== $targetRp) {
                $incompatible++;
                unset($tables['passkeys'][$index]);
            }
        }
        if ($incompatible > 0 && ! $skipIncompatiblePasskeys) {
            throw new InvalidArgumentException("{$incompatible} passkeys cannot be used with the target RP ID. Nothing was written; use --skip-incompatible-passkeys to omit them explicitly.");
        }
        $assurance = $payload['assurance'];
        $verificationRanks = ['discouraged' => 0, 'preferred' => 1, 'required' => 2];
        $targetVerification = $verificationRanks[(string) config('bherila-auth.passkeys.user_verification', 'preferred')] ?? -1;
        if (($assurance['code_after_password'] && ! config('auth-manager.sign_in.code_after_password'))
            || (! $assurance['code_only'] && config('auth-manager.sign_in.code_only'))
            || (! $assurance['trusted_devices'] && config('auth-manager.sign_in.trusted_devices'))
            || ($tables['passkeys'] !== [] && $targetVerification < $verificationRanks[$assurance['passkey_user_verification']])) {
            throw new InvalidArgumentException('Target sign-in assurance is weaker than the source. Match or strengthen the source code-after-password, code-only, trusted-device and passkey user-verification settings before import.');
        }
        $reset = 0;
        foreach ($tables['users'] as &$user) {
            if (! $this->compatibleHash((string) $user['password'])) {
                $reset++;
                if ($resetIncompatiblePasswords && (int) $user['credential_version'] >= PHP_INT_MAX) {
                    throw new InvalidArgumentException('A credential generation cannot be advanced safely. Nothing was written.');
                }
                if ($apply && $resetIncompatiblePasswords) {
                    // Nobody knows this random credential: the operator must provide recovery.
                    $user['password'] = Hash::make(Str::random(64));
                    $user['credential_version'] = (string) ((int) $user['credential_version'] + 1);
                }
            }
        }
        unset($user);
        if ($reset > 0 && ! $resetIncompatiblePasswords) {
            throw new InvalidArgumentException("{$reset} password hashes are incompatible with the target hasher. Nothing was written; align the hasher or use --reset-incompatible-passwords and arrange recovery.");
        }
        $users = array_fill_keys(array_column($tables['users'], 'id'), true);
        $historicalOwners = count(array_filter($tables['oauth_clients'], static fn (array $client): bool => $client['owner_id'] !== null && ! isset($users[$client['owner_id']])));
        $report = ['already_imported' => 0, 'passkeys_omitted' => $incompatible, 'passwords_requiring_reset' => $reset, 'historical_client_owners' => $historicalOwners, 'verification_codes_excluded' => 1, 'runtime_keys_excluded' => 1];
        foreach ($tables as $name => $rows) {
            $report[$name] = count($rows);
        }
        $this->assertFresh($db);
        if (! $apply) {
            return $report;
        }

        // DDL commits implicitly on MariaDB. Raise every floor before data writes;
        // interrupted imports remain safe to retry on the still-empty directory.
        $sequence = new TableSequence($db);
        foreach ($payload['sequence_floors'] as $name => $floor) {
            $sequence->raiseTo($this->table($name), $floor);
        }
        $db->transaction(function () use ($db, $tables, $checksum, $report): void {
            $this->assertFresh($db);
            // A fixed primary key serializes competing imports even when their
            // snapshots contain disjoint IDs under MariaDB repeatable-read.
            // Insert before rows so the losing transaction can never merge them.
            $db->table('directory_imports')->insert([
                'id' => 1,
                'checksum' => $checksum,
                'report' => json_encode($report, JSON_THROW_ON_ERROR),
                'created_at' => now(),
            ]);
            foreach ($tables as $name => $rows) {
                foreach (array_chunk($rows, 100) as $chunk) {
                    $db->table($this->table($name))->insert($chunk);
                }
            }
        });

        return $report;
    }

    /** @param array<string, mixed> $payload @return array<string, list<array<string, string|null>>> */
    private function validated(array $payload, Connection $db): array
    {
        if (array_keys($payload) !== ['source_issuer', 'source_rp_id', 'assurance', 'sequence_floors', 'tables']
            || ! is_string($payload['source_issuer']) || ! is_string($payload['source_rp_id']) || $payload['source_rp_id'] === ''
            || ! is_array($payload['tables']) || array_keys($payload['tables']) !== array_keys(self::COLUMNS)
            || ! is_array($payload['sequence_floors'])) {
            throw new InvalidArgumentException('Directory archive has invalid metadata or table fields.');
        }
        if (! is_array($payload['assurance'])
            || array_keys($payload['assurance']) !== ['code_after_password', 'code_only', 'trusted_devices', 'passkey_user_verification']
            || ! is_bool($payload['assurance']['code_after_password']) || ! is_bool($payload['assurance']['code_only'])
            || ! is_bool($payload['assurance']['trusted_devices'])
            || ! in_array($payload['assurance']['passkey_user_verification'], ['required', 'preferred', 'discouraged'], true)) {
            throw new InvalidArgumentException('Directory archive has invalid sign-in assurance metadata.');
        }
        $sequence = new TableSequence($db);
        if (! $sequence->supported()) {
            throw new InvalidArgumentException('Directory copy supports SQLite, MySQL and MariaDB only.');
        }
        $tables = [];
        $expectedFloors = [];
        foreach (self::COLUMNS as $name => $columns) {
            $this->assertColumns($db, $this->table($name), $columns);
            if (! is_array($payload['tables'][$name]) || ! array_is_list($payload['tables'][$name])) {
                throw new InvalidArgumentException('Directory archive has an invalid row collection.');
            }
            $tables[$name] = [];
            foreach ($payload['tables'][$name] as $packed) {
                if (! is_array($packed) || array_keys($packed) !== $columns) {
                    throw new InvalidArgumentException('Directory archive has unexpected row fields.');
                }
                $row = DirectoryArchive::unpackRow($packed);
                if ($name === 'oauth_clients') {
                    $row = $this->normalizeClient($row, true);
                }
                if ($name === 'users' && (! ctype_digit((string) $row['credential_version'])
                    || strlen((string) $row['credential_version']) > strlen((string) PHP_INT_MAX)
                    || (strlen((string) $row['credential_version']) === strlen((string) PHP_INT_MAX)
                        && strcmp((string) $row['credential_version'], (string) PHP_INT_MAX) > 0))) {
                    throw new InvalidArgumentException('A credential generation is outside the supported range.');
                }
                $tables[$name][] = $row;
            }
            if (in_array('id', $columns, true) && $name !== 'oauth_clients') {
                $expectedFloors[] = $name;
                $floor = $payload['sequence_floors'][$name] ?? null;
                if (! is_int($floor) || $floor < 1) {
                    throw new InvalidArgumentException('Directory archive has an invalid identifier floor.');
                }
                foreach ($tables[$name] as $row) {
                    if (! ctype_digit((string) $row['id']) || (int) $row['id'] < 1 || (int) $row['id'] >= $floor) {
                        throw new InvalidArgumentException('Directory archive identifier is outside its allocation floor.');
                    }
                }
            }
        }
        if (array_keys($payload['sequence_floors']) !== $expectedFloors) {
            throw new InvalidArgumentException('Directory archive has unexpected identifier floors.');
        }
        foreach ($tables['identity_tombstones'] as $row) {
            if (! ctype_digit((string) $row['subject']) || (int) $row['subject'] >= $payload['sequence_floors']['users']) {
                throw new InvalidArgumentException('Directory archive would reuse a tombstoned subject.');
            }
        }
        $this->assertReferences($tables, $payload['sequence_floors']['users']);

        return $tables;
    }

    /** @param array<string, mixed> $row @return array<string, mixed> */
    private function normalizeClient(array $row, bool $import): array
    {
        if (! in_array($row['provider'], [null, 'users', Mount::EMBEDDED_USER_PROVIDER], true)
            || ! in_array($row['owner_type'], [null, User::class], true)) {
            throw new InvalidArgumentException('A client belongs to a foreign user provider or owner model; it cannot be copied safely.');
        }
        if ($row['secret'] !== null && (($import && ! $this->compatibleHash((string) $row['secret']))
            || (password_get_info((string) $row['secret'])['algoName'] ?? 'unknown') === 'unknown')) {
            throw new InvalidArgumentException('A client secret is not a compatible portable hash; align the target hasher or rotate it before copying.');
        }
        $row['provider'] = $row['provider'] === null ? null : ($import && Mount::embedded() ? Mount::EMBEDDED_USER_PROVIDER : 'users');

        return $row;
    }

    private function assertFresh(Connection $db): void
    {
        foreach ([...array_keys(self::COLUMNS), 'directory_imports', 'oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_device_codes', 'sessions', 'trusted_devices', 'password_reset_tokens', 'invitation_acceptance_codes'] as $name) {
            if ($db->table($this->table($name))->exists()) {
                throw new InvalidArgumentException('The target directory is not fresh. No existing identity, client or credential may be adopted.');
            }
        }
    }

    private function compatibleHash(string $hash): bool
    {
        $algorithm = password_get_info($hash)['algoName'] ?? 'unknown';
        if ($algorithm === 'unknown') {
            return false;
        }
        $driver = (string) config('hashing.driver', 'bcrypt');
        $options = $driver === 'argon2id' ? 'argon' : $driver;
        if (! config('hashing.'.$options.'.verify', true)) {
            return true;
        }

        return $algorithm === match ($driver) {
            'bcrypt' => 'bcrypt',
            'argon' => 'argon2i',
            'argon2id' => 'argon2id',
            default => null,
        };
    }

    /** @param array<string, list<array<string, string|null>>> $tables */
    private function assertReferences(array $tables, int $userFloor): void
    {
        $ids = [];
        foreach ($tables as $name => $rows) {
            $seen = [];
            foreach ($rows as $row) {
                $key = isset($row['id']) ? $row['id'] : $row['oauth_client_id'].'/'.$row['subject'];
                if (isset($seen[$key])) {
                    throw new InvalidArgumentException('Directory archive repeats a primary identifier.');
                }
                $seen[$key] = true;
            }
            $ids[$name] = $seen;
        }
        $emails = [];
        foreach ($tables['users'] as $user) {
            $email = mb_strtolower(trim((string) $user['email']));
            if ($email === '' || isset($emails[$email])) {
                throw new InvalidArgumentException('Directory archive contains conflicting identity addresses.');
            }
            $emails[$email] = true;
        }
        foreach ($tables['oauth_clients'] as $client) {
            $owner = $client['owner_id'];
            if ($owner === null) {
                continue;
            }
            // Purging a person intentionally leaves their owned clients. Keep
            // the historical ownership marker: clearing it would make Passport
            // treat a formerly third-party client as trusted first-party.
            if ($client['owner_type'] !== User::class || ! ctype_digit($owner)
                || (int) $owner < 1 || (int) $owner >= $userFloor) {
                throw new InvalidArgumentException('A client ownership identifier is outside the allocated directory subject range.');
            }
        }
        $references = [
            'passkeys' => ['user_id' => 'users'],
            'oauth_client_grants' => ['subject' => 'users', 'oauth_client_id' => 'oauth_clients'],
            'registered_application_clients' => ['registered_application_id' => 'registered_applications', 'oauth_client_id' => 'oauth_clients'],
            'access_invitations' => ['inviter_id' => 'users', 'revoked_by' => 'users', 'accepted_user_id' => 'users', 'requesting_client_id' => 'oauth_clients'],
            'identity_tombstone_clients' => ['identity_tombstone_id' => 'identity_tombstones'],
        ];
        foreach ($references as $table => $columns) {
            foreach ($tables[$table] as $row) {
                foreach ($columns as $column => $parent) {
                    if ($row[$column] !== null && ! isset($ids[$parent][$row[$column]])) {
                        throw new InvalidArgumentException('Directory archive has a missing referenced identity, client or application.');
                    }
                }
            }
        }
    }

    /** @param list<string> $columns */
    private function assertColumns(Connection $db, string $table, array $columns): void
    {
        if (array_diff($columns, $db->getSchemaBuilder()->getColumnListing($table)) !== []) {
            throw new InvalidArgumentException('The directory schema is incompatible; apply the reviewed migrations first.');
        }
    }

    private function table(string $name): string
    {
        return $name === 'passkeys' ? (string) config('bherila-auth.passkeys.table', 'webauthn_credentials') : $name;
    }

    private function effectiveRpId(): string
    {
        return (string) (config('bherila-auth.passkeys.rp_id') ?: parse_url((string) config('app.url'), PHP_URL_HOST));
    }

    private function connection(): Connection
    {
        $db = DB::connection();
        if (config('passport.connection') !== null && DB::connection(config('passport.connection')) !== $db) {
            throw new InvalidArgumentException('Directory copy requires the provider and Passport to use the same connection.');
        }

        return $db;
    }
}
