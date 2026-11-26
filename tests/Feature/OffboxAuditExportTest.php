<?php

namespace Tests\Feature;

use BWH\AuthManager\Console\ProviderSchedule;
use BWH\AuthManager\Models\User;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Tests\TestCase;

class OffboxAuditExportTest extends TestCase
{
    use RefreshDatabase;

    private const COMMAND = 'auth-manager:audit-export';

    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->directory = sys_get_temp_dir().'/synthetic-audit-export-'.Str::uuid();
        Storage::fake('audit-export');
        config([
            'auth-manager.recovery.epoch' => 1,
            'auth-manager.recovery.audit_export.disk' => 'audit-export',
            'auth-manager.recovery.audit_export.prefix' => 'audit',
            'auth-manager.recovery.audit_export.batch_size' => 5000,
            'auth-manager.recovery.audit_export.state_path' => $this->directory.'/audit-export-state.json',
        ]);
        $this->travelTo(Carbon::parse('2026-11-25 12:00:00'));
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->directory);
        parent::tearDown();
    }

    public function test_without_a_disk_the_export_refuses_and_is_not_scheduled(): void
    {
        config(['auth-manager.recovery.audit_export.disk' => null]);
        $this->audit();

        $this->artisan(self::COMMAND)->expectsOutputToContain('AUTH_MANAGER_AUDIT_EXPORT_DISK is not set')->assertExitCode(1);
        $this->artisan(self::COMMAND, ['--status' => true])->expectsOutputToContain('AUTH_MANAGER_AUDIT_EXPORT_DISK is not set')->assertExitCode(1);
        $this->assertSame([], Storage::disk('audit-export')->allFiles());
        $this->assertFileDoesNotExist($this->directory.'/audit-export-state.json');
        $this->assertNull($this->scheduled());

        config(['auth-manager.recovery.audit_export.disk' => 'audit-export']);
        $event = $this->scheduled();
        $this->assertNotNull($event);
        $this->assertSame('0 * * * *', $event->expression);
        $this->assertTrue($event->withoutOverlapping);
    }

    public function test_the_first_run_exports_every_settled_row_in_bounded_objects_without_secrets(): void
    {
        config(['auth-manager.recovery.audit_export.batch_size' => 2]);
        $first = $this->audit([
            'user_id' => null,
            'email' => ' Person@Example.test ',
            'auth_method' => 'admin',
            'reason' => 'Synthetic reason.',
            'ip_address' => inet_pton('192.0.2.10'),
            'user_agent' => 'SyntheticBrowser/1.0',
            'session_id' => 'synthetic-session-identifier',
            'metadata' => json_encode(['oauth_client_ids' => ['7'], 'attempt_token' => 'synthetic-secret-value', 'nested' => ['password' => 'synthetic-secret-value', 'code' => 'synthetic-secret-value', 'name' => 'Example key']]),
        ]);
        foreach (range(2, 5) as $ignored) {
            $this->audit();
        }
        // Too recent: an earlier id could still be uncommitted, so it waits for the next run.
        $this->audit(at: Carbon::now()->subSeconds(10));

        $this->artisan(self::COMMAND)->expectsOutputToContain('Exported 5 audit rows in 3 objects')->assertExitCode(0);

        $this->assertSame([
            'audit/2026/11/25/e1-1-2.jsonl.gz',
            'audit/2026/11/25/e1-3-4.jsonl.gz',
            'audit/2026/11/25/e1-5-5.jsonl.gz',
        ], $this->objectNames());
        $rows = $this->rows('audit/2026/11/25/e1-1-2.jsonl.gz');
        $this->assertSame([$first, $first + 1], array_column($rows, 'id'));
        $this->assertSame([
            'id' => $first,
            'created_at' => '2026-11-25 11:50:00',
            'event' => 'synthetic_event',
            'succeeded' => true,
            'auth_method' => 'admin',
            'reason' => 'Synthetic reason.',
            'user_id' => null,
            'acting_user_id' => null,
            'email_sha256' => hash('sha256', 'person@example.test'),
            'session_sha256' => hash('sha256', 'synthetic-session-identifier'),
            'is_suspicious' => false,
            'metadata' => ['oauth_client_ids' => ['7'], 'attempt_token' => '[redacted]', 'nested' => ['password' => '[redacted]', 'code' => '[redacted]', 'name' => 'Example key']],
        ], $rows[0]);
        $everything = implode('', array_map(fn (string $path): string => (string) gzdecode((string) Storage::disk('audit-export')->get($path)), $this->objectNames()));
        foreach (['Person@Example.test', 'person@example.test', 'SyntheticBrowser', 'synthetic-session-identifier', 'synthetic-secret-value', '192.0.2.10', inet_pton('192.0.2.10')] as $secret) {
            $this->assertStringNotContainsString($secret, $everything);
        }

        $this->travel(2)->minutes();
        $this->artisan(self::COMMAND)->expectsOutputToContain('Exported 1 audit rows in 1 objects')->assertExitCode(0);
        $this->assertContains('audit/2026/11/25/e1-6-6.jsonl.gz', $this->objectNames());
    }

    public function test_a_later_run_exports_only_new_rows_and_a_repeated_run_changes_nothing(): void
    {
        $this->audit();
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-1-3.jsonl.gz'], $this->objectNames());
        $before = $this->snapshot();

        $this->artisan(self::COMMAND)->expectsOutputToContain('No new audit rows to export.')->assertExitCode(0);
        $this->assertSame($before, $this->snapshot());

        $this->travel(1)->hours();
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->expectsOutputToContain('Exported 2 audit rows in 1 objects')->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-1-3.jsonl.gz', 'audit/2026/11/25/e1-4-5.jsonl.gz'], $this->objectNames());
        $this->assertSame([4, 5], array_column($this->rows('audit/2026/11/25/e1-4-5.jsonl.gz'), 'id'));
        $this->assertSame($before['audit/2026/11/25/e1-1-3.jsonl.gz'], $this->snapshot()['audit/2026/11/25/e1-1-3.jsonl.gz']);

        $after = $this->snapshot();
        $this->artisan(self::COMMAND)->expectsOutputToContain('No new audit rows to export.')->assertExitCode(0);
        $this->assertSame($after, $this->snapshot());
    }

    public function test_a_restored_database_is_never_exported_again_and_never_changes_an_object(): void
    {
        foreach (range(1, 5) as $ignored) {
            $this->audit();
        }
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $before = $this->snapshot();

        // A restore from a backup holding three rows: the next row reuses id 4.
        $this->restoreTo(3);
        $this->artisan(self::COMMAND)->expectsOutputToContain('Raise AUTH_MANAGER_RECOVERY_EPOCH')->assertExitCode(1);
        $this->assertSame($before, $this->snapshot());

        $this->travel(1)->hours();
        $reused = $this->audit(['event' => 'synthetic_after_restore']);
        $this->assertSame(4, $reused);
        $this->artisan(self::COMMAND)->expectsOutputToContain('Raise AUTH_MANAGER_RECOVERY_EPOCH')->assertExitCode(1);
        $this->assertSame($before, $this->snapshot());

        config(['auth-manager.recovery.epoch' => 2]);
        $this->artisan(self::COMMAND)->expectsOutputToContain('Exported 1 audit rows in 1 objects')->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-1-5.jsonl.gz', 'audit/2026/11/25/e2-4-4.jsonl.gz'], $this->objectNames());
        $this->assertSame(['synthetic_after_restore'], array_column($this->rows('audit/2026/11/25/e2-4-4.jsonl.gz'), 'event'));
        $this->assertSame($before['audit/2026/11/25/e1-1-5.jsonl.gz'], $this->snapshot()['audit/2026/11/25/e1-1-5.jsonl.gz']);

        $after = $this->snapshot();
        $this->artisan(self::COMMAND)->expectsOutputToContain('No new audit rows to export.')->assertExitCode(0);
        $this->assertSame($after, $this->snapshot());
    }

    public function test_purging_the_identity_of_the_last_exported_row_is_not_a_rollback(): void
    {
        $user = (int) User::factory()->create(['email' => 'person@example.test'])->getKey();
        $this->audit();
        $this->audit(['user_id' => $user, 'acting_user_id' => $user, 'email' => 'person@example.test']);
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $before = $this->snapshot();

        // What a purge does to the account's audit rows (IdentityTombstonePurger and the foreign keys).
        DB::table('auth_audit_log')->where('user_id', $user)->update(['email' => null]);
        DB::table('auth_audit_log')->where('user_id', $user)->update(['user_id' => null, 'acting_user_id' => null]);
        DB::table('users')->where('id', $user)->delete();

        $this->artisan(self::COMMAND)->expectsOutputToContain('No new audit rows to export.')->assertExitCode(0);
        $this->audit();
        $this->artisan(self::COMMAND)->expectsOutputToContain('Exported 1 audit rows in 1 objects')->assertExitCode(0);
        $this->assertSame($before['audit/2026/11/25/e1-1-2.jsonl.gz'], $this->snapshot()['audit/2026/11/25/e1-1-2.jsonl.gz']);
    }

    public function test_a_raised_epoch_without_a_rollback_continues_after_the_last_exported_row(): void
    {
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);

        config(['auth-manager.recovery.epoch' => 2]);
        $this->travel(1)->hours();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-1-2.jsonl.gz', 'audit/2026/11/25/e2-3-3.jsonl.gz'], $this->objectNames());

        // A configuration rollback to an earlier epoch is refused, not exported under it.
        config(['auth-manager.recovery.epoch' => 1]);
        $this->travel(1)->hours();
        $this->audit();
        $before = $this->snapshot();
        $this->artisan(self::COMMAND)->expectsOutputToContain('is below the newest exported one')->assertExitCode(1);
        $this->assertSame($before, $this->snapshot());
    }

    public function test_an_existing_object_is_never_overwritten(): void
    {
        // A clock that ran ahead put the newest object under tomorrow's date.
        $this->travelTo(Carbon::parse('2026-11-26 12:00:00'));
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $this->assertSame(['audit/2026/11/26/e1-1-2.jsonl.gz'], $this->objectNames());

        $this->travelTo(Carbon::parse('2026-11-25 12:00:00'));
        $this->audit();
        $this->audit();
        Storage::disk('audit-export')->put('audit/2026/11/25/e1-3-4.jsonl.gz', 'synthetic existing object');
        $before = $this->snapshot();

        $this->artisan(self::COMMAND)->expectsOutputToContain('it is never overwritten')->assertExitCode(1);
        $this->assertSame($before, $this->snapshot());
    }

    public function test_the_local_state_is_the_fallback_only_for_its_own_destination(): void
    {
        $this->audit();
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);

        // Every object has expired out of the destination: resume from the recorded state.
        Storage::fake('audit-export');
        $this->travel(1)->hours();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-4-4.jsonl.gz'], $this->objectNames());

        // A different destination starts from the beginning.
        Storage::fake('second-audit-export');
        config(['auth-manager.recovery.audit_export.disk' => 'second-audit-export']);
        $this->artisan(self::COMMAND)->assertExitCode(0);
        $this->assertSame(['audit/2026/11/25/e1-1-4.jsonl.gz'], Storage::disk('second-audit-export')->allFiles());
    }

    public function test_status_reports_whether_the_export_is_current(): void
    {
        $this->audit();
        $this->audit();
        $this->artisan(self::COMMAND)->assertExitCode(0);

        $this->artisan(self::COMMAND, ['--status' => true])
            ->expectsOutputToContain('Exported through id: 2 (epoch 1)')
            ->expectsOutputToContain('The export is current.')
            ->assertExitCode(0);

        $this->audit(at: Carbon::now()->subHours(3));
        $this->artisan(self::COMMAND, ['--status' => true])
            ->expectsOutputToContain('Rows not yet exported: 1')
            ->expectsOutputToContain('The export is behind')
            ->assertExitCode(1);
        $this->assertSame(['audit/2026/11/25/e1-1-2.jsonl.gz'], $this->objectNames());
    }

    /** @param array<string, mixed> $attributes */
    private function audit(array $attributes = [], ?Carbon $at = null): int
    {
        $at ??= Carbon::now()->subMinutes(10);

        return (int) DB::table('auth_audit_log')->insertGetId([
            'event' => 'synthetic_event',
            'succeeded' => true,
            'created_at' => $at,
            'updated_at' => $at,
            ...$attributes,
        ]);
    }

    /** Drops every row after the given id and rewinds the id sequence, as restoring a backup does. */
    private function restoreTo(int $id): void
    {
        DB::table('auth_audit_log')->where('id', '>', $id)->delete();
        DB::statement("UPDATE sqlite_sequence SET seq = {$id} WHERE name = 'auth_audit_log'");
    }

    /** @return list<string> */
    private function objectNames(): array
    {
        $files = Storage::disk('audit-export')->allFiles();
        sort($files);

        return $files;
    }

    /** @return array<string, string> */
    private function snapshot(): array
    {
        $snapshot = [];
        foreach ($this->objectNames() as $path) {
            $snapshot[$path] = (string) Storage::disk('audit-export')->get($path);
        }

        return $snapshot;
    }

    /** @return list<array<string, mixed>> */
    private function rows(string $path): array
    {
        $lines = array_filter(explode("\n", (string) gzdecode((string) Storage::disk('audit-export')->get($path))));

        return array_values(array_map(static fn (string $line): array => json_decode($line, true, 16, JSON_THROW_ON_ERROR), $lines));
    }

    private function scheduled(): ?object
    {
        $schedule = new Schedule;
        ProviderSchedule::define($schedule);

        return collect($schedule->events())->first(static fn ($event): bool => str_contains((string) $event->command, self::COMMAND));
    }
}
