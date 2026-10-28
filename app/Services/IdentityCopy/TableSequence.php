<?php

namespace App\Services\IdentityCopy;

use Illuminate\Database\Connection;
use RuntimeException;

/**
 * Reads and raises the next identifier a table will allocate.
 *
 * A subject is a users-table identifier, and relying applications bind their accounts to it.
 * When identities are copied between instances, the receiving instance must never allocate an
 * identifier the sending instance already used, or a new person could inherit somebody else's
 * binding. The counter is engine state rather than data, so each supported engine is handled
 * explicitly and anything else is refused before a single row is written.
 */
final class TableSequence
{
    public function __construct(private readonly Connection $connection) {}

    /**
     * Whether this connection's engine is supported. Checked before any write.
     */
    public function supported(): bool
    {
        return in_array($this->connection->getDriverName(), ['mysql', 'mariadb', 'sqlite'], true);
    }

    /**
     * The identifier the table will allocate next. Never lower than the highest stored id + 1.
     */
    public function next(string $table): int
    {
        $highest = (int) $this->connection->table($table)->max('id');

        return max($highest + 1, $this->counter($table));
    }

    /**
     * Raise the counter so the next allocation is at least `$next`. Never lowers it.
     *
     * On MySQL and MariaDB this is DDL, which commits implicitly, so callers must not run it
     * inside a transaction they expect to roll back.
     *
     * @return bool Whether the counter moved.
     */
    public function raiseTo(string $table, int $next): bool
    {
        if ($next <= $this->next($table)) {
            return false;
        }

        $this->assertPlainIdentifier($table);

        match ($this->connection->getDriverName()) {
            'mysql', 'mariadb' => $this->connection->statement(sprintf('ALTER TABLE `%s` AUTO_INCREMENT = %d', $this->prefixed($table), $next)),
            'sqlite' => $this->raiseSqlite($table, $next),
            default => throw new RuntimeException('This database engine is not supported for identifier sequences.'),
        };

        if ($this->next($table) < $next) {
            throw new RuntimeException('The identifier sequence did not move to the requested value.');
        }

        return true;
    }

    private function counter(string $table): int
    {
        return match ($this->connection->getDriverName()) {
            'mysql', 'mariadb' => (int) $this->connection->selectOne(
                'SELECT AUTO_INCREMENT AS next_id FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
                [$this->prefixed($table)],
            )?->next_id,
            // An AUTOINCREMENT table records the highest id ever allocated in sqlite_sequence.
            'sqlite' => $this->sqliteSequence($table) + 1,
            default => throw new RuntimeException('This database engine is not supported for identifier sequences.'),
        };
    }

    private function sqliteSequence(string $table): int
    {
        $hasSequence = $this->connection->selectOne(
            "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'",
        );

        if ($hasSequence === null) {
            return 0;
        }

        return (int) $this->connection->selectOne(
            'SELECT seq FROM sqlite_sequence WHERE name = ?',
            [$this->prefixed($table)],
        )?->seq;
    }

    private function raiseSqlite(string $table, int $next): void
    {
        $name = $this->prefixed($table);
        $updated = $this->connection->update('UPDATE sqlite_sequence SET seq = ? WHERE name = ?', [$next - 1, $name]);

        if ($updated === 0) {
            $this->connection->insert('INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)', [$name, $next - 1]);
        }
    }

    private function prefixed(string $table): string
    {
        return $this->connection->getTablePrefix().$table;
    }

    private function assertPlainIdentifier(string $table): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $this->prefixed($table)) !== 1) {
            throw new RuntimeException('The table name is not a plain identifier.');
        }
    }
}
