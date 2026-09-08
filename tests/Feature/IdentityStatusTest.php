<?php

namespace Tests\Feature;

use App\Http\Controllers\OAuthUserController;
use App\Models\User;
use App\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class IdentityStatusTest extends TestCase
{
    use RefreshDatabase;

    private const ENDPOINT = '/api/reconciliation/identity-status';

    private function client(): array
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/oauth/callback']);

        return [$client, $client->plainSecret];
    }

    public function test_status_is_visible_only_to_a_current_granted_confidential_client(): void
    {
        [$client, $secret] = $this->client();
        [$other] = $this->client();
        $user = User::factory()->create(['name' => 'Example Person', 'email' => 'person@example.test', 'user_role' => 'user', 'credential_version' => 4]);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $other->id);
        $inactive = ['contract_version' => 1, 'active' => false];
        foreach ([(string) $user->id, 'unknown-subject'] as $subject) {
            $this->withBasicAuth((string) $client->id, $secret)->postJson(self::ENDPOINT, ['subject' => $subject])->assertOk()->assertExactJson($inactive)->assertHeader('Cache-Control', 'no-store, private');
        }
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $this->postJson(self::ENDPOINT, ['subject' => (string) $user->id])->assertOk()->assertExactJson([
            'contract_version' => 1, 'active' => true, 'subject' => (string) $user->id,
            'credential_version' => 4, 'name' => 'Example Person', 'email' => 'person@example.test',
        ])->assertHeader('Cache-Control', 'no-store, private');
        foreach (['0'.$user->id, $user->id.'suffix', ' '.$user->id.' '] as $subject) {
            $this->postJson(self::ENDPOINT, ['subject' => $subject])->assertOk()->assertExactJson($inactive);
        }
    }

    public function test_revalidation_reads_current_version_status_grant_and_deletion(): void
    {
        [$client, $secret] = $this->client();
        $user = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $this->withBasicAuth((string) $client->id, $secret);
        $payload = ['subject' => (string) $user->id];
        $this->postJson(self::ENDPOINT, $payload)->assertJsonPath('credential_version', 0);
        $user->forceFill(['credential_version' => 1])->save();
        $this->postJson(self::ENDPOINT, $payload)->assertJsonPath('credential_version', 1);
        $user->update(['disabled_at' => now()]);
        $this->postJson(self::ENDPOINT, $payload)->assertExactJson(['contract_version' => 1, 'active' => false]);
        $user->update(['disabled_at' => null]);
        app(OAuthClientGrantService::class)->revoke((string) $user->id, (string) $client->id);
        $this->postJson(self::ENDPOINT, $payload)->assertExactJson(['contract_version' => 1, 'active' => false]);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $user->delete();
        $this->postJson(self::ENDPOINT, $payload)->assertExactJson(['contract_version' => 1, 'active' => false]);
    }

    public function test_invalid_revoked_public_and_dynamic_clients_cannot_read_status(): void
    {
        [$client, $secret] = $this->client();
        $user = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $body = ['subject' => (string) $user->id];
        $this->postJson(self::ENDPOINT, $body)->assertUnauthorized();
        $this->withBasicAuth((string) $client->id, 'wrong-secret')->postJson(self::ENDPOINT, $body)->assertUnauthorized();
        $client->forceFill(['revoked' => true])->save();
        $this->withBasicAuth((string) $client->id, $secret)->postJson(self::ENDPOINT, $body)->assertUnauthorized();
        $client->forceFill(['revoked' => false, 'dynamically_registered_at' => now()])->save();
        config(['auth-manager.profile' => 'resource', 'auth-manager.dynamic_client_registration' => true]);
        $this->postJson(self::ENDPOINT, $body)->assertUnauthorized()->assertHeader('Cache-Control', 'no-store, private');
        $public = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Public Example', ['https://public.example.test/callback'], false);
        $this->withBasicAuth((string) $public->id, 'anything')->postJson(self::ENDPOINT, $body)->assertUnauthorized();
    }

    public function test_subject_validation_and_throttling_are_bounded(): void
    {
        [$client, $secret] = $this->client();
        $this->withBasicAuth((string) $client->id, $secret);
        foreach ([[], ['subject' => 1], ['subject' => ['invalid']], ['subject' => str_repeat('x', 256)]] as $body) {
            $this->postJson(self::ENDPOINT, $body)->assertUnprocessable()->assertHeader('Cache-Control', 'no-store, private');
        }
        for ($i = 0; $i < 56; $i++) {
            $this->postJson(self::ENDPOINT, ['subject' => 'unknown'])->assertOk();
        }
        $this->postJson(self::ENDPOINT, ['subject' => 'unknown'])->assertTooManyRequests()->assertHeader('Cache-Control', 'no-store, private');
    }

    public function test_oauth_identity_exposes_generation_but_never_disabled_identity(): void
    {
        $user = User::factory()->create(['user_role' => 'user', 'credential_version' => 3]);
        $request = Request::create('/api/oauth/user');
        $request->setUserResolver(fn (): User => $user);
        $response = app(OAuthUserController::class)($request);
        $this->assertSame(3, $response->getData(true)['credential_version']);
        $user->update(['disabled_at' => now()]);
        $this->expectException(HttpException::class);
        app(OAuthUserController::class)($request);
    }
}
