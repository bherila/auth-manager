<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\IdentityCopy\IdentityCopyDocument;
use BWH\AuthManager\Services\IdentityCopy\TableSequence;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/**
 * The identifier sequence is engine state. On MySQL and MariaDB it is the table's AUTO_INCREMENT,
 * raised with DDL that commits implicitly, so SQLite cannot stand in for it. Runs only in the
 * MariaDB lane (phpunit.mariadb.xml), against a throwaway server. Each test rebuilds the schema
 * with migrate:fresh instead of RefreshDatabase, whose wrapping transaction the DDL would commit.
 */
#[Group('mariadb')]
class IdentityCopyMariaDbTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->artisan('migrate:fresh')->assertSuccessful();
    }

    public function test_the_sequence_is_read_and_raised_through_auto_increment(): void
    {
        $sequence = new TableSequence(DB::connection());
        $this->assertTrue($sequence->supported());
        $this->assertSame(1, $sequence->next('users'));

        $this->assertTrue($sequence->raiseTo('users', 500));
        $this->assertSame(500, $sequence->next('users'));
        $this->assertFalse($sequence->raiseTo('users', 20), 'A sequence is never lowered.');
        $this->assertSame(500, $sequence->next('users'));

        $this->assertSame(500, User::factory()->create()->id);
    }

    public function test_import_preserves_subjects_and_moves_auto_increment_past_the_floor(): void
    {
        $path = storage_path('framework/testing/identity-copy-'.Str::random(12).'.json');
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, json_encode([
            'format' => IdentityCopyDocument::FORMAT,
            'version' => 1,
            'next_id_floor' => 36,
            'users' => [$this->entry(1), $this->entry(34)],
        ]));

        try {
            $this->artisan('identity:import', ['--input' => $path, '--apply' => true])
                ->expectsOutputToContain('sequence  next id 1 -> 36')
                ->assertSuccessful();

            // MariaDB already moved the counter to 35 when id 34 was inserted explicitly; the
            // floor covers subjects the sender used and deleted, which that alone would not.
            $this->assertSame(36, User::factory()->create()->id);

            $this->artisan('identity:import', ['--input' => $path, '--apply' => true])
                ->expectsOutputToContain('users     created 0, unchanged 2')
                ->assertSuccessful();
        } finally {
            @unlink($path);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(int $id): array
    {
        return [
            'id' => $id,
            'name' => "Person {$id}",
            'email' => "person-{$id}@example.test",
            'email_verified_at' => '2026-01-01 00:00:00',
            'password' => Hash::make("password-{$id}"),
            'user_role' => 'user',
            'disabled_at' => null,
            'last_login_date' => null,
            'created_at' => '2026-01-01 00:00:00',
            'updated_at' => '2026-01-01 00:00:00',
        ];
    }
}
