<?php

namespace Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Models\IdentityTombstone;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\TestLoginService;
use BWH\AuthManager\Support\TestLoginAddresses;
use Carbon\CarbonImmutable;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class TestLoginLifecycleTest extends TestCase
{
    use RefreshDatabase;

    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->freezeTime();
        $this->directory = sys_get_temp_dir().'/test-login-'.Str::uuid();
        File::makeDirectory($this->directory, 0700);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->directory);
        parent::tearDown();
    }

    public function test_create_writes_credentials_once_to_a_private_file_and_only_grants_selected_static_clients(): void
    {
        $selected = $this->client();
        $other = $this->client();
        [$user, $credentials, $path] = $this->create(['--client' => [$selected->id]]);
        $this->assertTrue($user->isTestLogin());
        $this->assertSame(['user'], $user->roleNames());
        $this->assertSame(72, strlen($credentials['password']));
        $this->assertTrue(Hash::check($credentials['password'], $user->password));
        $this->assertSame((string) $user->id, $credentials['subject']);
        $this->assertSame(0600, fileperms($path) & 0777);
        $this->assertStringNotContainsString($credentials['password'], Artisan::output());
        $this->assertStringNotContainsString($user->password, Artisan::output());
        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $user->id, 'oauth_client_id' => $selected->id]);
        $this->assertDatabaseMissing('oauth_client_grants', ['subject' => $user->id, 'oauth_client_id' => $other->id]);
        $audit = AuthAuditLog::where('event', 'test_login_created')->sole();
        $this->assertSame($user->id, $audit->user_id);
        $this->assertNull($audit->acting_user_id);
        $this->assertSame('console', $audit->auth_method);
        $this->assertStringNotContainsString($credentials['password'], json_encode($audit->getAttributes()));
        $this->assertStringNotContainsString($user->password, json_encode($audit->getAttributes()));
    }

    public function test_a_failed_private_file_write_rolls_back_the_identity_grants_and_audit_without_overwriting(): void
    {
        $path = $this->directory.'/occupied.json';
        file_put_contents($path, 'existing private file');
        $this->artisan('auth-manager:test-logins', $this->arguments(['--output' => $path]))->assertFailed();
        $this->assertSame('existing private file', file_get_contents($path));
        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('oauth_client_grants', 0);
        $this->assertSame(0, AuthAuditLog::where('event', 'test_login_created')->count());
    }

    public function test_output_under_a_web_root_or_through_a_symlink_is_refused_without_creating_a_login(): void
    {
        $this->artisan('auth-manager:test-logins', $this->arguments(['--output' => public_path('synthetic-secret.json')]))->assertFailed();
        $this->assertFileDoesNotExist(public_path('synthetic-secret.json'));
        $link = $this->directory.'/alias';
        $this->assertTrue(symlink($this->directory, $link));
        $this->artisan('auth-manager:test-logins', $this->arguments(['--output' => $link.'/synthetic-secret.json']))->assertFailed();
        $this->assertDatabaseCount('users', 0);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function invalidCreations(): array
    {
        return [
            'no expiry' => [['--expires-at' => null]],
            'relative expiry' => [['--expires-at' => 'tomorrow']],
            'impossible date' => [['--expires-at' => '2026-02-31T12:00:00Z']],
            'past expiry' => [['--expires-at' => '2020-01-01T00:00:00Z']],
            'no clients' => [['--client' => []]],
            'no output' => [['--output' => null]],
            'no name' => [['--name' => '']],
        ];
    }

    #[DataProvider('invalidCreations')]
    public function test_creation_requires_explicit_bounded_inputs(array $overrides): void
    {
        $this->artisan('auth-manager:test-logins', $this->arguments($overrides))->assertFailed();
        $this->assertDatabaseCount('users', 0);
    }

    public function test_future_expiry_is_bounded_and_creation_never_adopts_an_existing_or_retired_identity(): void
    {
        $this->artisan('auth-manager:test-logins', $this->arguments(['--expires-at' => now('UTC')->addHours(25)->format('Y-m-d\TH:i:s\Z')]))->assertFailed();
        $existing = User::factory()->create(['email' => 'browser@example.test', 'user_role' => 'admin']);
        $original = $existing->fresh()->getAttributes();
        $this->artisan('auth-manager:test-logins', $this->arguments(['--email' => strtoupper('browser@example.test')]))->assertFailed();
        $this->assertSame($original, $existing->fresh()->getAttributes());
        $existing->delete();
        $this->artisan('auth-manager:test-logins', $this->arguments())->assertFailed();
        $this->assertSame(1, User::withTrashed()->count());
    }

    public function test_revoked_dynamic_foreign_and_unknown_clients_are_refused(): void
    {
        $revoked = $this->client(['revoked' => true]);
        $dynamic = $this->client(['dynamically_registered_at' => now()]);
        $foreign = $this->client(['provider' => 'unrelated-directory']);
        $wrongGrant = $this->client(['grant_types' => ['client_credentials']]);
        foreach ([$revoked->id, $dynamic->id, $foreign->id, $wrongGrant->id, (string) Str::uuid()] as $id) {
            $this->artisan('auth-manager:test-logins', $this->arguments(['--client' => [$id]]))->assertFailed();
        }
        $this->assertDatabaseCount('users', 0);
    }

    public function test_domain_policy_has_reserved_boundaries_and_exact_case_insensitive_extra_domains(): void
    {
        foreach (['example.com', 'nested.example.net', 'fixture.test', 'fixture.invalid', 'fixture.example', 'fixture.localhost'] as $domain) {
            $this->assertTrue(TestLoginAddresses::allows('browser@'.$domain));
        }
        foreach (['notexample.com', 'example.com.invalid-suffix', 'example.org.attacker'] as $domain) {
            $this->assertFalse(TestLoginAddresses::allows('browser@'.$domain));
        }
        $this->assertFalse(TestLoginAddresses::allows('not-an-address'));
        // A configured example outside RFC 2606 exercises the exact-domain rule.
        $extra = 'sandbox.example.edu';
        config(['auth-manager.test_logins.allowed_domains' => [strtoupper($extra)]]);
        $this->assertTrue(TestLoginAddresses::allows('browser@'.$extra));
        $this->assertFalse(TestLoginAddresses::allows('browser@nested.'.$extra));
        $this->assertSame(['sandbox.example.edu'], TestLoginAddresses::configuredDomains(' Sandbox.Example.Edu, sandbox.example.edu '));
    }

    public function test_extend_never_reenables_a_manually_disabled_login(): void
    {
        [$user] = $this->create();
        app(TestLoginService::class)->disable($user->id);
        $disabledAt = $user->fresh()->disabled_at->toISOString();
        $this->artisan('auth-manager:test-logins', ['action' => 'extend', 'subject' => $user->id, '--expires-at' => now('UTC')->addHours(2)->format('Y-m-d\TH:i:s\Z')])->assertSuccessful();
        $this->assertSame($disabledAt, $user->fresh()->disabled_at->toISOString());
        $this->assertFalse($user->fresh()->canLogin());
    }

    public function test_extending_after_expiry_before_scheduler_revokes_old_sessions_and_credentials(): void
    {
        [$user, $credentials] = $this->create();
        $client = PassportClient::query()->firstOrFail();
        DB::table('oauth_access_tokens')->insert(['id' => 'synthetic-token', 'user_id' => $user->id, 'client_id' => $client->id, 'revoked' => false]);
        DB::table('oauth_refresh_tokens')->insert(['id' => 'synthetic-refresh', 'access_token_id' => 'synthetic-token', 'revoked' => false]);
        DB::table('sessions')->insert(['id' => 'synthetic-session', 'user_id' => $user->id, 'payload' => '', 'last_activity' => now()->timestamp]);
        DB::table('auth_two_factor_attempts')->insert(['user_id' => $user->id, 'token' => 'synthetic-attempt', 'code' => '123456', 'expires_at' => now()->addDay()]);
        DB::table('password_reset_tokens')->insert(['email' => $user->email, 'token' => 'synthetic-reset']);
        $user->forceFill(['remember_token' => 'synthetic-remember'])->save();
        $this->travelTo(CarbonImmutable::parse($credentials['expires_at'])->addSecond());
        $this->assertFalse($user->fresh()->canLogin());
        $this->assertNull($user->fresh()->disabled_at);
        app(TestLoginService::class)->extend($user->id, CarbonImmutable::now('UTC')->addHour());
        $fresh = $user->fresh();
        $this->assertTrue($fresh->canLogin());
        $this->assertSame(1, $fresh->credential_version);
        $this->assertNull($fresh->remember_token);
        $this->assertTrue((bool) DB::table('oauth_access_tokens')->value('revoked'));
        $this->assertTrue((bool) DB::table('oauth_refresh_tokens')->value('revoked'));
        foreach (['sessions', 'auth_two_factor_attempts', 'password_reset_tokens'] as $table) {
            $this->assertDatabaseCount($table, 0);
        }
    }

    public function test_expiry_cleanup_is_idempotent_at_the_utc_deadline_and_does_not_touch_ordinary_accounts(): void
    {
        config(['app.timezone' => 'America/Los_Angeles']);
        $timezone = date_default_timezone_get();
        [$user, $credentials] = $this->create();
        $ordinary = User::factory()->create();
        $this->travelTo(CarbonImmutable::parse($credentials['expires_at'])->subSecond());
        $this->assertSame(0, app(TestLoginService::class)->expire());
        $this->travelTo(CarbonImmutable::parse($credentials['expires_at']));
        $this->assertFalse($user->fresh()->canLogin());
        $this->assertSame(1, app(TestLoginService::class)->expire());
        $this->assertSame(0, app(TestLoginService::class)->expire());
        $this->assertSame(1, $user->fresh()->credential_version);
        $this->assertNull($ordinary->fresh()->disabled_at);
        $this->assertSame(1, AuthAuditLog::where('event', 'test_login_expired')->count());
        $this->assertSame($timezone, date_default_timezone_get());
    }

    public function test_disable_and_retire_refuse_ordinary_subjects_and_retirement_keeps_the_flag_and_tombstone(): void
    {
        $ordinary = User::factory()->create();
        foreach (['disable', 'retire', 'extend'] as $action) {
            $args = ['action' => $action, 'subject' => $ordinary->id];
            if ($action === 'extend') {
                $args['--expires-at'] = now('UTC')->addHour()->format('Y-m-d\TH:i:s\Z');
            }
            $this->artisan('auth-manager:test-logins', $args)->assertFailed();
        }
        [$user] = $this->create();
        $this->artisan('auth-manager:test-logins', ['action' => 'disable', 'subject' => $user->id])->assertSuccessful();
        $this->artisan('auth-manager:test-logins', ['action' => 'retire', 'subject' => $user->id])->assertSuccessful();
        $retired = User::withTrashed()->findOrFail($user->id);
        $this->assertTrue($retired->trashed());
        $this->assertTrue($retired->isTestLogin());
        $this->assertFalse($retired->canLogin());
        $this->assertSame($user->id, IdentityTombstone::sole()->subject);
        $this->assertGreaterThan(0, IdentityTombstone::sole()->clients()->count());
        $this->artisan('auth-manager:test-logins', ['action' => 'retire', 'subject' => $user->id])->assertSuccessful();
        $this->assertSame(1, IdentityTombstone::count());
        $this->assertSame(1, AuthAuditLog::where('event', 'test_login_retired')->count());
        $this->assertNull($ordinary->fresh()->disabled_at);
        $this->artisan('auth-manager:test-logins', ['action' => 'extend', 'subject' => $user->id, '--expires-at' => now('UTC')->addHours(2)->format('Y-m-d\TH:i:s\Z')])->assertFailed();
    }

    public function test_the_scheduler_registers_the_bounded_expiry_command_with_overlap_protection(): void
    {
        $event = collect(app(Schedule::class)->events())->first(static fn ($event): bool => str_contains($event->command ?? '', 'auth-manager:test-logins'));
        $this->assertNotNull($event);
        $this->assertSame('* * * * *', $event->expression);
        $this->assertTrue($event->withoutOverlapping);
    }

    /** @param array<string, mixed> $attributes */
    private function client(array $attributes = []): PassportClient
    {
        return PassportClient::query()->create([
            'id' => (string) Str::uuid(), 'name' => 'Synthetic browser client',
            'secret' => Hash::make('synthetic-client-secret'), 'grant_types' => ['authorization_code'],
            'redirect_uris' => ['https://app.example.test/oauth/callback'], 'revoked' => false,
            'dynamically_registered_at' => null, ...$attributes,
        ]);
    }

    /** @return array<string, mixed> */
    private function arguments(array $overrides = []): array
    {
        return ['action' => 'create', '--name' => 'Synthetic browser login', '--email' => 'browser@example.test',
            '--expires-at' => now('UTC')->addHour()->format('Y-m-d\TH:i:s\Z'), '--client' => [$this->client()->id],
            '--output' => $this->directory.'/'.Str::uuid().'.json', ...$overrides];
    }

    /** @return array{User, array<string, mixed>, string} */
    private function create(array $overrides = []): array
    {
        $args = $this->arguments($overrides);
        $this->assertSame(0, Artisan::call('auth-manager:test-logins', $args), Artisan::output());
        $credentials = json_decode(file_get_contents($args['--output']), true, flags: JSON_THROW_ON_ERROR);

        return [User::query()->findOrFail($credentials['subject']), $credentials, $args['--output']];
    }
}
