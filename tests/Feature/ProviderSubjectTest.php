<?php

namespace Tests\Feature;

use BWH\AuthManager\Http\Controllers\OAuthUserController;
use BWH\AuthManager\Models\IdentityTombstone;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use BWH\AuthManager\Support\ApplicationGrantHolders;
use BWH\AuthManager\Support\ProviderSubjects;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\AccessToken;
use Laravel\Passport\ClientRepository;
use RuntimeException;
use Tests\TestCase;

/** Every edge that leaves the provider names an account by `users.subject`, never its row id. */
class ProviderSubjectTest extends TestCase
{
    use RefreshDatabase;

    private const STATUS = '/api/reconciliation/identity-status';

    /** A synthetic opaque subject, unrelated to any id. */
    private const OPAQUE = '01JSYNTHETICSUBJECTAAAAAAA';

    public function test_a_new_account_is_known_by_its_own_id_and_its_subject_never_changes(): void
    {
        $user = User::factory()->create();

        $this->assertSame((string) $user->id, $user->subject);
        $this->assertSame((string) $user->id, $user->providerSubject());
        $this->assertSame((string) $user->id, DB::table('users')->where('id', $user->id)->value('subject'));

        $this->expectException(RuntimeException::class);
        $user->forceFill(['subject' => 'SomethingElse1'])->save();
    }

    public function test_opaque_subjects_are_off_by_default_and_give_new_accounts_a_random_ulid_when_on(): void
    {
        $this->assertFalse(config('auth-manager.subjects.opaque'));
        $before = User::factory()->create(['user_role' => 'user']);
        $this->assertSame((string) $before->id, $before->providerSubject());

        config(['auth-manager.subjects.opaque' => true]);
        $first = User::factory()->create(['user_role' => 'user']);
        $second = User::factory()->create(['user_role' => 'user']);
        foreach ([$first, $second] as $user) {
            $this->assertMatchesRegularExpression('/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/D', $user->providerSubject());
            $this->assertTrue(Str::isUlid($user->providerSubject()));
            $this->assertNotSame((string) $user->id, $user->providerSubject());
            $this->assertSame($user->providerSubject(), DB::table('users')->where('id', $user->id)->value('subject'));
        }
        $this->assertNotSame($first->providerSubject(), $second->providerSubject());
        // Existing accounts keep theirs, and a carried subject is still kept.
        $this->assertSame((string) $before->id, $before->fresh()->providerSubject());
        $this->assertSame(self::OPAQUE, User::factory()->create(['subject' => self::OPAQUE])->providerSubject());

        // The ULID is what every edge sends and what identity status finds.
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);
        app(OAuthClientGrantService::class)->grant((string) $first->id, (string) $client->id);
        $this->withBasicAuth((string) $client->id, (string) $client->plainSecret);
        $this->postJson(self::STATUS, ['subject' => $first->providerSubject()])->assertOk()
            ->assertJsonPath('active', true)->assertJsonPath('subject', $first->providerSubject());
        $this->postJson(self::STATUS, ['subject' => (string) $first->id])->assertOk()->assertJsonPath('active', false);

        config(['auth-manager.subjects.opaque' => false]);
        $after = User::factory()->create();
        $this->assertSame((string) $after->id, $after->providerSubject());
    }

    public function test_an_account_written_without_a_subject_is_still_known_by_its_id(): void
    {
        // The previous release inserts accounts without the column while the migration runs.
        DB::table('users')->insert(['id' => 41, 'name' => 'Person 41', 'email' => 'person-41@example.test', 'password' => 'not-a-real-hash', 'user_role' => 'user']);

        $user = User::query()->whereProviderSubject('41')->firstOrFail();
        $this->assertNull($user->subject);
        $this->assertSame('41', $user->providerSubject());
        $this->assertNull(User::query()->whereProviderSubject('041')->first());
    }

    public function test_a_carried_subject_is_kept_and_a_used_retired_or_foreign_numeric_one_is_refused_without_a_row(): void
    {
        $carried = User::factory()->create(['subject' => self::OPAQUE]);
        $this->assertSame(self::OPAQUE, $carried->providerSubject());
        DB::table('identity_tombstones')->insert([
            'public_id' => (string) Str::uuid(), 'subject' => 900, 'provider_subject' => 'SyntheticRetired01',
            'tombstoned_at' => now(), 'purge_after' => now()->addDays(30), 'created_at' => now(), 'updated_at' => now(),
        ]);
        DB::table('identity_tombstones')->insert([
            'public_id' => (string) Str::uuid(), 'subject' => 901, 'provider_subject' => null,
            'tombstoned_at' => now(), 'purge_after' => now()->addDays(30), 'created_at' => now(), 'updated_at' => now(),
        ]);
        $this->assertTrue(app(ProviderSubjects::class)->retired('SyntheticRetired01'));
        $this->assertTrue(app(ProviderSubjects::class)->retired('901'));
        $this->assertFalse(app(ProviderSubjects::class)->retired('900'));

        $refused = [
            'already in use' => ['subject' => self::OPAQUE],
            'held by a deleted identity' => ['subject' => 'SyntheticRetired01'],
            'all digits but not its own id' => ['subject' => '777777'],
            'not a subject' => ['subject' => 'has-a-dash'],
            'an id a deleted identity held' => ['id' => 901],
        ];
        foreach ($refused as $case => $attributes) {
            $issued = true;
            try {
                User::factory()->create($attributes);
            } catch (RuntimeException|QueryException) {
                $issued = false;
            }
            $this->assertFalse($issued, "A subject that is {$case} was issued.");
            $this->assertSame(1, User::withTrashed()->count(), $case);
        }
    }

    public function test_sign_in_identity_sends_the_subject_column(): void
    {
        $user = User::factory()->create(['user_role' => 'user', 'subject' => self::OPAQUE]);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);
        DB::table('oauth_access_tokens')->insert([
            'id' => 'synthetic-access-token', 'user_id' => $user->id, 'client_id' => $client->id,
            'scopes' => '[]', 'revoked' => false, 'credential_version' => 0,
        ]);
        $user->withAccessToken(new AccessToken(['oauth_access_token_id' => 'synthetic-access-token', 'oauth_client_id' => (string) $client->id, 'oauth_user_id' => (string) $user->id]));
        $request = Request::create('/api/oauth/user');
        $request->setUserResolver(fn (): User => $user);

        $this->assertSame(self::OPAQUE, app(OAuthUserController::class)($request)->getData(true)['sub']);
    }

    public function test_identity_status_finds_numeric_and_opaque_subjects_by_the_subject_column_only(): void
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);
        $numeric = User::factory()->create(['user_role' => 'user']);
        $opaque = User::factory()->create(['user_role' => 'user', 'subject' => self::OPAQUE, 'credential_version' => 2]);
        foreach ([$numeric, $opaque] as $user) {
            app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        }
        $this->withBasicAuth((string) $client->id, (string) $client->plainSecret);

        $this->postJson(self::STATUS, ['subject' => (string) $numeric->id])->assertOk()
            ->assertJsonPath('active', true)->assertJsonPath('subject', (string) $numeric->id);
        $this->postJson(self::STATUS, ['subject' => self::OPAQUE])->assertOk()
            ->assertJsonPath('active', true)->assertJsonPath('subject', self::OPAQUE)->assertJsonPath('credential_version', 2);

        // The opaque account's row id is not its subject, and subjects are case-sensitive.
        foreach ([(string) $opaque->id, strtolower(self::OPAQUE)] as $subject) {
            $this->postJson(self::STATUS, ['subject' => $subject])->assertOk()->assertJsonPath('active', false)->assertJsonMissingPath('subject');
        }
    }

    public function test_the_tombstone_feed_and_the_tombstone_carry_the_subject_column(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user', 'subject' => self::OPAQUE]);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);

        $this->actingAs($admin)->deleteJson("/api/admin/users/{$target->id}")
            ->assertAccepted()->assertJsonPath('tombstone.subject', self::OPAQUE);
        $tombstone = IdentityTombstone::query()->firstOrFail();
        $this->assertSame(self::OPAQUE, $tombstone->provider_subject);
        $this->assertSame($target->id, $tombstone->subject);
        $this->assertTrue(app(ProviderSubjects::class)->retired(self::OPAQUE));

        $this->withBasicAuth((string) $client->id, (string) $client->plainSecret)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertOk()->assertJsonPath('data.0.subject', self::OPAQUE);
    }

    public function test_a_tombstone_written_without_a_text_subject_is_still_reported_by_its_id(): void
    {
        DB::table('identity_tombstones')->insert([
            'public_id' => (string) Str::uuid(), 'subject' => 58,
            'tombstoned_at' => now(), 'purge_after' => now()->addDays(30), 'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->assertSame('58', IdentityTombstone::query()->firstOrFail()->providerSubject());
    }

    public function test_application_access_lists_and_resolves_people_by_subject(): void
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);
        $application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application', 'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $application->clients()->attach($client->id);
        $person = User::factory()->create(['user_role' => 'user', 'name' => 'Example Person', 'subject' => self::OPAQUE]);
        app(OAuthClientGrantService::class)->grant((string) $person->id, (string) $client->id);
        $holders = app(ApplicationGrantHolders::class);

        $this->assertSame([['subject' => self::OPAQUE, 'name' => 'Example Person', 'email' => $person->email]], $holders->search($application, 'Example')['people']);
        $this->assertTrue($person->is($holders->person($application, self::OPAQUE)));
        $this->assertNull($holders->person($application, (string) $person->id));
    }

    public function test_identity_copy_refuses_to_export_an_account_known_by_an_opaque_subject(): void
    {
        $user = User::factory()->create(['subject' => self::OPAQUE]);

        $this->assertSame(1, Artisan::call('identity:export', ['--subject' => [(string) $user->id], '--allow-terminal' => true]));
        $this->assertStringContainsString('opaque subject', Artisan::output());
    }
}
