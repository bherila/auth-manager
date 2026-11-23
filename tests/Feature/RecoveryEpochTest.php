<?php

namespace Tests\Feature;

use BWH\AuthManager\Http\Controllers\OAuthUserController;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\AccessToken;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class RecoveryEpochTest extends TestCase
{
    use RefreshDatabase;

    private const STATUS = '/api/reconciliation/identity-status';

    private string $directory;

    private string $highWater;

    private PassportClient $client;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();
        $this->directory = sys_get_temp_dir().'/synthetic-recovery-'.Str::uuid();
        $this->highWater = $this->directory.'/high-water.json';
        $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);
        $this->user = User::factory()->create(['user_role' => 'user', 'credential_version' => 2]);
        app(OAuthClientGrantService::class)->grant((string) $this->user->id, (string) $this->client->id);
        $this->withBasicAuth((string) $this->client->id, (string) $this->client->plainSecret);
    }

    protected function tearDown(): void
    {
        @unlink($this->highWater);
        @rmdir($this->directory);
        parent::tearDown();
    }

    public function test_the_recovery_epoch_is_sent_with_the_sign_in_identity_and_every_status_answer(): void
    {
        config(['auth-manager.recovery.epoch' => 3]);

        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk()->assertExactJson([
            'contract_version' => 1, 'active' => true, 'subject' => $this->user->providerSubject(), 'credential_version' => 2, 'recovery_epoch' => 3,
        ]);
        $this->postJson(self::STATUS, ['subject' => 'Unknown1'])->assertOk()->assertExactJson([
            'contract_version' => 1, 'active' => false, 'recovery_epoch' => 3,
        ]);

        DB::table('oauth_access_tokens')->insert([
            'id' => 'synthetic-access-token', 'user_id' => $this->user->id, 'client_id' => $this->client->id,
            'scopes' => '[]', 'revoked' => false, 'credential_version' => 2,
        ]);
        $this->user->withAccessToken(new AccessToken(['oauth_access_token_id' => 'synthetic-access-token', 'oauth_client_id' => (string) $this->client->id, 'oauth_user_id' => (string) $this->user->id]));
        $request = Request::create('/api/oauth/user');
        $request->setUserResolver(fn (): User => $this->user);
        $identity = app(OAuthUserController::class)($request)->getData(true);
        $this->assertSame(3, $identity['recovery_epoch']);
        $this->assertSame(2, $identity['credential_version']);
    }

    public function test_a_database_behind_the_high_water_mark_is_refused_until_the_epoch_is_raised(): void
    {
        $this->guard(epoch: 1);
        $this->audit(3);
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk()->assertJsonPath('active', true);
        $highest = (int) DB::table('auth_audit_log')->max('id');
        $this->assertSame(['epoch' => 1, 'high_water' => $highest], $this->recorded());

        // Growth is recorded.
        $this->audit(2);
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk();
        $highest = (int) DB::table('auth_audit_log')->max('id');
        $this->assertSame(['epoch' => 1, 'high_water' => $highest], $this->recorded());

        // A restore rolls the log back: status is refused for everyone, with nothing disclosed.
        DB::table('auth_audit_log')->where('id', '>', $highest - 2)->delete();
        foreach ([$this->user->providerSubject(), 'Unknown1'] as $subject) {
            $this->postJson(self::STATUS, ['subject' => $subject])->assertStatus(503)
                ->assertHeader('Retry-After', '60')->assertHeader('Cache-Control', 'no-store, private')
                ->assertJsonMissingPath('active')->assertJsonMissingPath('recovery_epoch');
        }
        $this->assertSame(['epoch' => 1, 'high_water' => $highest], $this->recorded());

        // Raising the epoch is the operator's declaration; it starts a new record.
        $this->guard(epoch: 2);
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk()->assertJsonPath('recovery_epoch', 2);
        $this->assertSame(['epoch' => 2, 'high_water' => $highest - 2], $this->recorded());

        // A configuration that lowers the epoch again is refused too.
        $this->guard(epoch: 1);
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertStatus(503);
    }

    public function test_the_guard_can_be_turned_off_and_fails_closed_on_a_record_it_cannot_trust(): void
    {
        $this->guard(epoch: 1);
        $this->audit(1);
        mkdir($this->directory, 0700, true);
        file_put_contents($this->highWater, json_encode(['epoch' => 1, 'high_water' => 1000]));
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertStatus(503);

        config(['auth-manager.recovery.high_water_guard' => false]);
        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk()->assertJsonPath('active', true);

        config(['auth-manager.recovery.high_water_guard' => true]);
        foreach (['not json', '{"epoch":1}', '{"epoch":"1","high_water":1}', '{"epoch":0,"high_water":1}'] as $malformed) {
            file_put_contents($this->highWater, $malformed);
            $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertStatus(503);
        }
        $this->assertSame('{"epoch":0,"high_water":1}', file_get_contents($this->highWater));
    }

    public function test_the_first_request_starts_the_record(): void
    {
        $this->guard(epoch: 4);
        $this->audit(2);

        $this->postJson(self::STATUS, ['subject' => $this->user->providerSubject()])->assertOk()->assertJsonPath('recovery_epoch', 4);
        $this->assertSame(['epoch' => 4, 'high_water' => (int) DB::table('auth_audit_log')->max('id')], $this->recorded());
    }

    public function test_the_settings_default_to_epoch_one_with_the_guard_on_and_refuse_invalid_values(): void
    {
        $config = $this->configWith([]);
        $this->assertSame(1, $config['recovery']['epoch']);
        $this->assertTrue($config['recovery']['high_water_guard']);
        $this->assertSame(storage_path('app/private/auth-manager/recovery-high-water.json'), $config['recovery']['high_water_path']);

        $config = $this->configWith(['AUTH_MANAGER_RECOVERY_EPOCH' => '7', 'AUTH_MANAGER_RECOVERY_HIGH_WATER_GUARD' => 'false', 'AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH' => '/srv/example/high-water.json']);
        $this->assertSame(7, $config['recovery']['epoch']);
        $this->assertFalse($config['recovery']['high_water_guard']);
        $this->assertSame('/srv/example/high-water.json', $config['recovery']['high_water_path']);

        $refused = [
            ['AUTH_MANAGER_RECOVERY_EPOCH' => '0'],
            ['AUTH_MANAGER_RECOVERY_EPOCH' => '-1'],
            ['AUTH_MANAGER_RECOVERY_EPOCH' => 'two'],
            ['AUTH_MANAGER_RECOVERY_HIGH_WATER_GUARD' => 'maybe'],
            ['AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH' => 'relative/high-water.json'],
        ];
        foreach ($refused as $environment) {
            try {
                $this->configWith($environment);
                $this->fail('An invalid recovery setting was accepted: '.json_encode($environment));
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    private function guard(int $epoch): void
    {
        config(['auth-manager.recovery' => ['epoch' => $epoch, 'high_water_guard' => true, 'high_water_path' => $this->highWater]]);
    }

    private function audit(int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            DB::table('auth_audit_log')->insert(['event' => 'synthetic_event', 'succeeded' => true, 'created_at' => now(), 'updated_at' => now()]);
        }
    }

    /** @return array<string, mixed> */
    private function recorded(): array
    {
        return json_decode((string) file_get_contents($this->highWater), true, 4, JSON_THROW_ON_ERROR);
    }

    /**
     * Evaluate config/auth-manager.php with exactly these recovery variables set and the others unset.
     *
     * @param  array<string, string>  $environment
     * @return array<string, mixed>
     */
    private function configWith(array $environment): array
    {
        $names = ['AUTH_MANAGER_RECOVERY_EPOCH', 'AUTH_MANAGER_RECOVERY_HIGH_WATER_GUARD', 'AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH'];
        $saved = [];
        foreach ($names as $name) {
            $saved[$name] = [$_SERVER[$name] ?? null, $_ENV[$name] ?? null, getenv($name)];
            unset($_SERVER[$name], $_ENV[$name]);
            putenv($name);
            if (isset($environment[$name])) {
                $_SERVER[$name] = $_ENV[$name] = $environment[$name];
                putenv($name.'='.$environment[$name]);
            }
        }
        try {
            return require config_path('auth-manager.php');
        } finally {
            foreach ($saved as $name => [$server, $env, $process]) {
                unset($_SERVER[$name], $_ENV[$name]);
                putenv($name);
                if ($server !== null) {
                    $_SERVER[$name] = $server;
                }
                if ($env !== null) {
                    $_ENV[$name] = $env;
                }
                if ($process !== false) {
                    putenv($name.'='.$process);
                }
            }
        }
    }
}
