<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\IdentityCopy\IdentityCopyDocument;
use App\Services\IdentityCopy\TableSequence;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

class IdentityCopyTest extends TestCase
{
    use RefreshDatabase;

    private string $documentPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->documentPath = storage_path('framework/testing/identity-copy-'.Str::random(12).'.json');
        @mkdir(dirname($this->documentPath), 0777, true);
    }

    protected function tearDown(): void
    {
        @unlink($this->documentPath);
        parent::tearDown();
    }

    public function test_export_writes_only_the_named_subjects_with_hashes_and_nothing_bound_to_this_instance(): void
    {
        $this->person(3, 'three@example.test', 'admin,user');
        $this->person(5, 'five@example.test', disabledAt: '2026-01-02 03:04:05');
        $this->person(8, 'eight@example.test');
        DB::table('users')->where('id', 3)->update(['remember_token' => 'remembered-on-the-sender']);

        $document = $this->export(['3', '5']);

        $this->assertSame([3, 5], array_column($document['users'], 'id'));
        $this->assertSame(IdentityCopyDocument::COLUMNS, array_keys($document['users'][0]));
        $this->assertTrue(Hash::check('password-3', $document['users'][0]['password']));
        $this->assertSame('admin,user', $document['users'][0]['user_role']);
        $this->assertSame('2026-01-02 03:04:05', $document['users'][1]['disabled_at']);
        $this->assertSame(9, $document['next_id_floor']);
        $this->assertStringNotContainsString('remembered-on-the-sender', json_encode($document));
    }

    public function test_export_refuses_missing_and_deleted_subjects(): void
    {
        $this->person(1, 'one@example.test');
        $this->person(2, 'two@example.test');
        DB::table('users')->where('id', 2)->update(['deleted_at' => now()]);

        $this->assertSame(1, Artisan::call('identity:export', ['--subject' => ['1', '4']]));
        $this->assertStringContainsString('No such subject: 4', Artisan::output());

        $this->assertSame(1, Artisan::call('identity:export', ['--subject' => ['1', '2']]));
        $this->assertStringContainsString('Deleted subjects cannot be copied: 2', Artisan::output());
        $this->assertStringNotContainsString('"users"', Artisan::output());

        $this->assertSame(2, Artisan::call('identity:export'));
        $this->assertSame(2, Artisan::call('identity:export', ['--subject' => ['one']]));
    }

    public function test_export_floor_is_above_every_identifier_this_instance_has_used(): void
    {
        $this->person(1, 'one@example.test');
        $this->person(30, 'thirty@example.test');
        DB::table('users')->where('id', 30)->update(['deleted_at' => now()]);
        $this->tombstone(44);

        $this->assertSame(45, $this->export(['1'])['next_id_floor']);
    }

    public function test_dry_run_reports_the_plan_and_writes_nothing(): void
    {
        $client = $this->client();
        $this->writeDocument(10, [$this->entry(7, 'seven@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--grant-client' => [$client]])
            ->expectsOutputToContain('Dry run. Nothing will be written.')
            ->expectsOutputToContain('users     created 1, unchanged 0')
            ->expectsOutputToContain('grants    created 1')
            ->expectsOutputToContain('sequence  next id 1 -> 10')
            ->assertSuccessful();

        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('oauth_client_grants', 0);
        $this->assertSame(1, $this->sequence()->next('users'));
    }

    public function test_apply_preserves_subjects_hashes_and_status_and_grants_only_people_who_may_sign_in(): void
    {
        $client = $this->client();
        $other = $this->client();
        $this->writeDocument(35, [
            $this->entry(1, 'one@example.test', 'admin,user'),
            $this->entry(7, 'seven@example.test'),
            $this->entry(25, 'disabled@example.test', disabledAt: '2026-03-04 05:06:07'),
            $this->entry(26, 'no-role@example.test', 'service'),
        ]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true, '--grant-client' => [$client]])
            ->expectsOutputToContain('users     created 4, unchanged 0')
            ->expectsOutputToContain('grants    created 2')
            ->assertSuccessful();

        $this->assertSame([1, 7, 25, 26], DB::table('users')->orderBy('id')->pluck('id')->map('intval')->all());
        $this->assertTrue(Hash::check('password-7', (string) DB::table('users')->where('id', 7)->value('password')));
        $this->assertSame('admin,user', DB::table('users')->where('id', 1)->value('user_role'));
        $this->assertSame('2026-03-04 05:06:07', IdentityCopyDocument::timestamp(DB::table('users')->where('id', 25)->value('disabled_at')));
        $this->assertNull(DB::table('users')->where('id', 7)->value('remember_token'));
        $this->assertSame([1, 7], DB::table('oauth_client_grants')->where('oauth_client_id', $client)->orderBy('subject')->pluck('subject')->map('intval')->all());
        $this->assertDatabaseMissing('oauth_client_grants', ['oauth_client_id' => $other]);
        $this->assertSame(4, DB::table('auth_audit_log')->where('event', 'identity_copied_in')->count());
        $this->assertDatabaseCount('webauthn_credentials', 0);
    }

    public function test_rerun_after_apply_changes_nothing(): void
    {
        $client = $this->client();
        $this->writeDocument(35, [$this->entry(1, 'one@example.test'), $this->entry(7, 'seven@example.test')]);
        $arguments = ['--input' => $this->documentPath, '--apply' => true, '--grant-client' => [$client]];
        $this->artisan('identity:import', $arguments)->assertSuccessful();
        DB::table('users')->where('id', 7)->update(['last_login_date' => now(), 'updated_at' => now()]);

        $this->artisan('identity:import', $arguments)
            ->expectsOutputToContain('users     created 0, unchanged 2')
            ->expectsOutputToContain('grants    created 0')
            ->expectsOutputToContain('sequence  next id 35 -> 35 (already at or above the floor)')
            ->assertSuccessful();

        $this->assertDatabaseCount('users', 2);
        $this->assertSame(2, DB::table('oauth_client_grants')->count());
        $this->assertSame(2, DB::table('auth_audit_log')->where('event', 'identity_copied_in')->count());
    }

    public function test_a_subject_held_here_by_a_different_person_refuses_the_whole_document(): void
    {
        $this->person(7, 'someone-else@example.test');
        $this->writeDocument(35, [$this->entry(1, 'one@example.test'), $this->entry(7, 'seven@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('Subject 7 already exists here with different email, password')
            ->expectsOutputToContain('Nothing was written.')
            ->assertFailed();

        $this->assertDatabaseMissing('users', ['id' => 1]);
        $this->assertSame(8, $this->sequence()->next('users'));
    }

    public function test_an_address_held_here_by_another_subject_refuses_the_whole_document(): void
    {
        $this->person(3, 'Seven@Example.test');
        $this->writeDocument(35, [$this->entry(1, 'one@example.test'), $this->entry(7, 'seven@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain("Subject 7's address belongs to subject 3 on this instance.")
            ->assertFailed();

        $this->assertDatabaseMissing('users', ['id' => 1]);
    }

    public function test_a_subject_deleted_here_is_never_recreated(): void
    {
        $this->tombstone(7);
        $this->writeDocument(35, [$this->entry(7, 'seven@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('Subject 7 was deleted on this instance.')
            ->assertFailed();

        $this->person(9, 'nine@example.test');
        DB::table('users')->where('id', 9)->update(['deleted_at' => now()]);
        $this->writeDocument(35, [$this->entry(9, 'nine@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('Subject 9 was deleted on this instance.')
            ->assertFailed();

        $this->assertDatabaseMissing('users', ['id' => 7]);
    }

    public function test_a_receiver_already_holding_other_subjects_below_the_floor_is_refused(): void
    {
        $this->person(5, 'local@example.test');
        $this->tombstone(6);
        $this->writeDocument(35, [$this->entry(1, 'one@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('Subjects below the floor are already used here by people this document does not carry: 5, 6.')
            ->expectsOutputToContain('Nothing was written.')
            ->assertFailed();

        $this->assertDatabaseMissing('users', ['id' => 1]);

        // Someone created here after a copy holds a subject at or above the floor, which is fine.
        $this->person(40, 'later@example.test');
        DB::table('users')->where('id', 5)->delete();
        DB::table('identity_tombstones')->delete();
        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])->assertSuccessful();
    }

    public function test_people_created_after_the_copy_never_receive_a_copied_or_used_subject(): void
    {
        $this->writeDocument(35, [$this->entry(1, 'one@example.test'), $this->entry(7, 'seven@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true, '--next-id-at-least' => '40'])
            ->expectsOutputToContain('sequence  next id 1 -> 40')
            ->assertSuccessful();

        $created = User::factory()->create();
        $this->assertSame(40, $created->id);
    }

    public function test_the_sequence_moves_before_anyone_is_written_and_a_failure_writes_nothing(): void
    {
        $this->app->bind(TableSequence::class, static fn ($app, array $parameters): TableSequence => new class($parameters['connection']) extends TableSequence
        {
            public function raiseTo(string $table, int $next): bool
            {
                throw new \RuntimeException('ALTER command denied');
            }
        });
        $this->writeDocument(35, [$this->entry(1, 'one@example.test')]);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('The identifier sequence could not be raised (ALTER command denied). Nothing was written.')
            ->assertFailed();

        $this->assertDatabaseCount('users', 0);
        $this->assertSame(0, DB::table('auth_audit_log')->where('event', 'identity_copied_in')->count());
    }

    public function test_mysql_counters_are_read_with_the_statistics_cache_off(): void
    {
        $builder = \Mockery::mock();
        $builder->shouldReceive('max')->with('id')->andReturn(41);
        $connection = \Mockery::mock(Connection::class);
        $connection->shouldReceive('getDriverName')->andReturn('mysql');
        $connection->shouldReceive('getTablePrefix')->andReturn('');
        $connection->shouldReceive('table')->with('users')->andReturn($builder);
        $connection->shouldReceive('statement')->once()->with('SET SESSION information_schema_stats_expiry = 0')->andReturn(true);
        $connection->shouldReceive('selectOne')->andReturn((object) ['next_id' => 57]);

        $sequence = new TableSequence($connection);

        $this->assertSame(57, $sequence->next('users'));
        $this->assertSame(57, $sequence->next('users'));
    }

    public function test_an_unknown_or_revoked_grant_client_refuses_before_writing(): void
    {
        $revoked = $this->client(revoked: true);
        $this->writeDocument(35, [$this->entry(1, 'one@example.test')]);

        foreach ([$revoked, (string) Str::uuid()] as $client) {
            $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true, '--grant-client' => [$client]])
                ->expectsOutputToContain('Not an active OAuth client on this instance')
                ->assertFailed();
        }

        $this->assertDatabaseCount('users', 0);
    }

    public function test_malformed_documents_are_refused(): void
    {
        $plaintext = $this->entry(1, 'one@example.test');
        $plaintext['password'] = 'not-a-hash';

        $cases = [
            'not a document' => 'nonsense',
            'plaintext password' => $this->document(35, [$plaintext]),
            'id at the floor' => $this->document(7, [$this->entry(7, 'seven@example.test')]),
            'duplicate address' => $this->document(35, [$this->entry(1, 'same@example.test'), $this->entry(2, 'SAME@example.test')]),
            'extra field' => json_encode(['format' => IdentityCopyDocument::FORMAT, 'version' => 1, 'next_id_floor' => 9, 'users' => [$this->entry(1, 'one@example.test') + ['remember_token' => 'x']]]),
            'other format' => json_encode(['format' => 'something-else', 'version' => 1, 'next_id_floor' => 9, 'users' => [$this->entry(1, 'one@example.test')]]),
        ];

        foreach ($cases as $case => $json) {
            file_put_contents($this->documentPath, $json);
            $this->assertSame(1, Artisan::call('identity:import', ['--input' => $this->documentPath, '--apply' => true]), $case);
            $this->assertStringContainsString('Nothing was written.', Artisan::output(), $case);
        }

        $this->assertDatabaseCount('users', 0);
    }

    public function test_an_export_round_trips_into_an_empty_instance(): void
    {
        $this->person(2, 'two@example.test', 'admin');
        $this->person(8, 'eight@example.test');
        $this->tombstone(12);
        $json = json_encode($this->export(['2', '8']));

        DB::table('identity_tombstones')->delete();
        DB::table('users')->delete();
        file_put_contents($this->documentPath, $json);

        $this->artisan('identity:import', ['--input' => $this->documentPath, '--apply' => true])
            ->expectsOutputToContain('users     created 2, unchanged 0')
            ->assertSuccessful();

        $this->assertTrue(Hash::check('password-8', (string) DB::table('users')->where('id', 8)->value('password')));
        $this->assertSame(13, $this->sequence()->next('users'));
    }

    /**
     * @param  list<string>  $subjects
     * @return array<string, mixed>
     */
    private function export(array $subjects): array
    {
        $this->assertSame(0, Artisan::call('identity:export', ['--subject' => $subjects]));
        $firstLine = strtok(Artisan::output(), "\n");

        return json_decode((string) $firstLine, true, 16, JSON_THROW_ON_ERROR);
    }

    private function person(int $id, string $email, string $role = 'user', ?string $disabledAt = null): void
    {
        DB::table('users')->insert([
            'id' => $id,
            'name' => "Person {$id}",
            'email' => $email,
            'email_verified_at' => '2026-01-01 00:00:00',
            'password' => Hash::make("password-{$id}"),
            'user_role' => $role,
            'disabled_at' => $disabledAt,
            'created_at' => '2026-01-01 00:00:00',
            'updated_at' => '2026-01-01 00:00:00',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(int $id, string $email, string $role = 'user', ?string $disabledAt = null): array
    {
        return [
            'id' => $id,
            'name' => "Person {$id}",
            'email' => $email,
            'email_verified_at' => '2026-01-01 00:00:00',
            'password' => Hash::make("password-{$id}"),
            'user_role' => $role,
            'disabled_at' => $disabledAt,
            'last_login_date' => null,
            'created_at' => '2026-01-01 00:00:00',
            'updated_at' => '2026-01-01 00:00:00',
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $users
     */
    private function document(int $floor, array $users): string
    {
        return (string) json_encode(['format' => IdentityCopyDocument::FORMAT, 'version' => 1, 'next_id_floor' => $floor, 'users' => $users]);
    }

    /**
     * @param  list<array<string, mixed>>  $users
     */
    private function writeDocument(int $floor, array $users): void
    {
        file_put_contents($this->documentPath, $this->document($floor, $users));
    }

    private function tombstone(int $subject): void
    {
        DB::table('identity_tombstones')->insert([
            'public_id' => (string) Str::uuid(),
            'subject' => $subject,
            'tombstoned_at' => now(),
            'purge_after' => now()->addDays(30),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function client(bool $revoked = false): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => 'Example Application',
            'secret' => 'secret',
            'redirect_uris' => json_encode(['https://app.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code']),
            'revoked' => $revoked,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    private function sequence(): TableSequence
    {
        return new TableSequence(DB::connection());
    }
}
