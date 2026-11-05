<?php

namespace BWH\AuthManager\Services\DirectoryCopy;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\IdentityCopy\TableSequence;
use BWH\AuthManager\Support\Mount;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
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
                if (in_array('id', $columns, true) && $name !== 'oauth_clients') {
                    $floors[$name] = $sequence->next($table);
                }
                $tables[$name] = array_map(DirectoryArchive::packRow(...), $rows);
            }
            $floors['users'] = max($floors['users'], (int) $db->table('identity_tombstones')->max('subject') + 1);

            return [
                'source_issuer' => (string) config('auth-manager.issuer'),
                'source_rp_id' => $this->effectiveRpId(),
                'sequence_floors' => $floors,
                'tables' => $tables,
            ];
        });
    }

    /** @param array<string, mixed> $payload @return array<string, int> */
    public function import(string $checksum, array $payload, bool $apply, bool $skipIncompatiblePasskeys = false): array
    {
        $db = $this->connection();
        $tables = $this->validated($payload, $db);
        $incompatible = 0;
        foreach ($tables['passkeys'] as $index => $row) {
            $rp = $row['rp_id'] ?? $payload['source_rp_id'];
            if ($rp !== $this->effectiveRpId() || $payload['source_rp_id'] !== $this->effectiveRpId()) {
                $incompatible++;
                unset($tables['passkeys'][$index]);
            }
        }
        if ($incompatible > 0 && ! $skipIncompatiblePasskeys) {
            throw new InvalidArgumentException("{$incompatible} passkeys cannot be used with the target RP ID. Nothing was written; use --skip-incompatible-passkeys to omit them explicitly.");
        }
        $report = ['already_imported' => 0, 'passkeys_omitted' => $incompatible, 'verification_codes_discarded' => 1, 'runtime_keys_not_copied' => 1];
        foreach ($tables as $name => $rows) {
            $report[$name] = count($rows);
        }
        $receipt = $db->table('directory_imports')->where('checksum', $checksum)->first();
        if ($receipt !== null) {
            $report = json_decode($receipt->report, true, 32, JSON_THROW_ON_ERROR);
            $report['already_imported'] = 1;

            return $report;
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
            foreach ($tables as $name => $rows) {
                foreach (array_chunk($rows, 100) as $chunk) {
                    $db->table($this->table($name))->insert($chunk);
                }
            }
            $db->table('directory_imports')->insert([
                'checksum' => $checksum,
                'report' => json_encode($report, JSON_THROW_ON_ERROR),
                'created_at' => now(),
            ]);
        });

        return $report;
    }

    /** @param array<string, mixed> $payload @return array<string, list<array<string, string|null>>> */
    private function validated(array $payload, Connection $db): array
    {
        if (array_keys($payload) !== ['source_issuer', 'source_rp_id', 'sequence_floors', 'tables']
            || ! is_string($payload['source_issuer']) || ! is_string($payload['source_rp_id']) || $payload['source_rp_id'] === ''
            || ! is_array($payload['tables']) || array_keys($payload['tables']) !== array_keys(self::COLUMNS)
            || ! is_array($payload['sequence_floors'])) {
            throw new InvalidArgumentException('Directory archive has invalid metadata or table fields.');
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
                if ($name === 'users' && (password_get_info((string) $row['password'])['algoName'] ?? 'unknown') === 'unknown') {
                    throw new InvalidArgumentException('A directory password hash is unsupported; arrange password recovery before copying.');
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

        return $tables;
    }

    /** @param array<string, mixed> $row @return array<string, mixed> */
    private function normalizeClient(array $row, bool $import): array
    {
        if (! in_array($row['provider'], [null, 'users', Mount::EMBEDDED_USER_PROVIDER], true)
            || ! in_array($row['owner_type'], [null, User::class], true)) {
            throw new InvalidArgumentException('A client belongs to a foreign user provider or owner model; it cannot be copied safely.');
        }
        if ($row['secret'] !== null && (password_get_info((string) $row['secret'])['algoName'] ?? 'unknown') === 'unknown') {
            throw new InvalidArgumentException('A client secret is not a portable recognized hash; rotate it before copying.');
        }
        $row['provider'] = $row['provider'] === null ? null : ($import && Mount::embedded() ? Mount::EMBEDDED_USER_PROVIDER : 'users');

        return $row;
    }

    private function assertFresh(Connection $db): void
    {
        foreach ([...array_keys(self::COLUMNS), 'directory_imports', 'oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'sessions', 'trusted_devices', 'password_reset_tokens'] as $name) {
            if ($db->table($this->table($name))->exists()) {
                throw new InvalidArgumentException('The target directory is not fresh. No existing identity, client or credential may be adopted.');
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
