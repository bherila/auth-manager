<?php

namespace Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\TestLoginTicket;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class TestLoginTicketTest extends TestCase
{
    use RefreshDatabase;

    private PassportClient $client;

    private User $person;

    private array $payload;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Synthetic Application', ['https://app.example.test/callback']);
        RegisteredApplication::create(['key' => 'synthetic', 'name' => 'Synthetic Application', 'launch_url' => 'https://app.example.test', 'enabled' => true])->clients()->attach($this->client->id);
        config(['auth-manager.test_logins.ticket_clients' => [(string) $this->client->id]]);
        $this->person = User::factory()->make(['name' => 'Synthetic Person', 'email' => 'person@example.test', 'password' => 'synthetic-password', 'user_role' => 'user', 'email_verified_at' => null]);
        $this->person->forceFill(['is_test_login' => true, 'test_login_expires_at' => now('UTC')->addHour()])->save();
        app(OAuthClientGrantService::class)->grant((string) $this->person->id, (string) $this->client->id);
        $this->payload = ['subject' => $this->person->providerSubject(), 'password' => 'synthetic-password', 'authorization' => [
            'client_id' => (string) $this->client->id, 'redirect_uri' => 'https://app.example.test/callback', 'response_type' => 'code',
            'state' => str_repeat('a', 40), 'code_challenge' => str_repeat('b', 43), 'code_challenge_method' => 'S256',
        ]];
        $this->withBasicAuth((string) $this->client->id, $this->client->plainSecret);
    }

    private function ticket(): string
    {
        $response = $this->postJson('/api/test-login-tickets', $this->payload)->assertCreated()->assertJsonPath('contract_version', 1)->assertHeader('Cache-Control', 'no-store, private');
        $uri = $response->json('confirmation_uri');
        $this->assertSame(route('auth-manager.test-logins.show'), strtok($uri, '#'));
        $this->assertNull(parse_url($uri, PHP_URL_QUERY));
        parse_str(parse_url($uri, PHP_URL_FRAGMENT), $fragment);

        return $fragment['ticket'];
    }

    public function test_explicit_confirmation_consumes_once_and_records_only_password_assurance_without_email_or_enrollment_proof(): void
    {
        $old = User::factory()->create();
        $this->actingAs($old)->withSession([RequireRecentPasskeyAuthentication::SESSION_KEY => ['old' => true]]);
        $token = $this->ticket();
        $this->get('/test-logins/confirm')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->assertAuthenticatedAs($old);
        $this->postJson('/test-logins/preview', ['ticket' => $token])->assertExactJson(['name' => 'Synthetic Person', 'application' => 'Synthetic Application']);
        $this->assertNull(TestLoginTicket::sole()->used_at);
        $response = $this->postJson('/test-logins/confirm', ['ticket' => $token])->assertOk();
        $this->assertSame('/oauth/authorize?'.http_build_query($this->payload['authorization']), $response->json('redirect_uri'));
        $this->assertAuthenticatedAs($this->person);
        $this->assertSame(['pwd'], session(AuthenticationContext::SESSION_KEY)['amr']);
        $this->assertSame(AuthenticationRequirement::ACR_SINGLE, session(AuthenticationContext::SESSION_KEY)['acr']);
        $this->assertFalse(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertNull($this->person->fresh()->email_verified_at);
        $this->assertNotNull(TestLoginTicket::sole()->used_at);
        $this->postJson('/test-logins/confirm', ['ticket' => $token])->assertForbidden();
        $this->assertSame(1, AuthAuditLog::where('event', 'test_login_ticket_used')->count());
        $this->assertStringNotContainsString($token, json_encode(DB::table('test_login_tickets')->get()));
        $this->assertStringNotContainsString('synthetic-password', json_encode(DB::table('test_login_tickets')->get()));
        $this->assertStringNotContainsString($token, json_encode(AuthAuditLog::all()));
    }

    #[DataProvider('denials')]
    public function test_issuance_checks_independent_identity_and_client_constraints(string $condition): void
    {
        $this->deny($condition);
        $this->postJson('/api/test-login-tickets', $this->payload)->assertStatus($condition === 'revoked' ? 401 : 403);
        $this->assertDatabaseCount('test_login_tickets', 0);
    }

    public static function denials(): array
    {
        return array_map(static fn ($v) => [$v], ['ordinary', 'admin', 'disabled', 'deleted', 'expired', 'ungranted', 'dynamic', 'revoked', 'off', 'registry-disabled', 'wrong-password', 'wrong-subject']);
    }

    private function deny(string $condition): void
    {
        match ($condition) {
            'ordinary' => DB::table('users')->where('id', $this->person->id)->update(['is_test_login' => false]),
            'admin' => DB::table('users')->where('id', $this->person->id)->update(['user_role' => 'admin']),
            'disabled' => $this->person->update(['disabled_at' => now()]),
            'deleted' => $this->person->delete(),
            'expired' => $this->person->forceFill(['test_login_expires_at' => now()->subSecond()])->save(),
            'ungranted' => app(OAuthClientGrantService::class)->revoke((string) $this->person->id, (string) $this->client->id),
            'dynamic' => $this->client->forceFill(['dynamically_registered_at' => now()])->save(),
            'revoked' => $this->client->update(['revoked' => true]),
            'off' => config(['auth-manager.test_logins.ticket_clients' => []]),
            'registry-disabled' => RegisteredApplication::query()->update(['enabled' => false]),
            'wrong-password' => $this->payload['password'] = 'wrong',
            'wrong-subject' => $this->payload['subject'] = 'unknown-subject',
        };
    }

    #[DataProvider('revocations')]
    public function test_ticket_rechecks_current_authority_before_preview_and_consumption(string $condition): void
    {
        $token = $this->ticket();
        if ($condition === 'generation') {
            $this->person->increment('credential_version');
        } elseif ($condition === 'ticket-expired') {
            $this->travel(61)->seconds();
        } elseif ($condition === 'callback-changed') {
            $this->client->update(['redirect_uris' => ['https://other.example.test/callback']]);
        } else {
            $this->deny($condition);
        }
        $this->postJson('/test-logins/preview', ['ticket' => $token])->assertForbidden();
        $this->postJson('/test-logins/confirm', ['ticket' => $token])->assertForbidden();
        $this->assertGuest();
        $this->assertNull(TestLoginTicket::sole()->used_at);
    }

    public static function revocations(): array
    {
        return array_map(static fn ($v) => [$v], ['disabled', 'deleted', 'expired', 'ungranted', 'dynamic', 'revoked', 'off', 'registry-disabled', 'generation', 'ticket-expired', 'callback-changed']);
    }

    #[DataProvider('badAuthorization')]
    public function test_authorization_is_bound_to_the_authenticated_client_callback_state_and_pkce(array $changes): void
    {
        $this->payload['authorization'] = [...$this->payload['authorization'], ...$changes];
        $this->postJson('/api/test-login-tickets', $this->payload)->assertForbidden();
    }

    public static function badAuthorization(): array
    {
        return array_map(static fn ($v) => [$v], [
            ['client_id' => 'other'], ['redirect_uri' => 'https://other.example.test/callback'], ['redirect_uri' => '//evil.example.test'],
            ['response_type' => 'token'], ['state' => 'short'], ['state' => []], ['code_challenge' => 'short'],
            ['code_challenge_method' => 'plain'], ['resource' => 'https://resource.example.test'], ['prompt' => 'none'], ['scope' => "read\nwrite"],
        ]);
    }

    public function test_both_client_secret_and_synthetic_password_are_required_and_lifetime_is_capped_by_the_identity(): void
    {
        $this->withBasicAuth((string) $this->client->id, 'wrong')->postJson('/api/test-login-tickets', $this->payload)->assertUnauthorized();
        $this->withBasicAuth((string) $this->client->id, $this->client->plainSecret);
        $this->person->forceFill(['test_login_expires_at' => now('UTC')->addSeconds(10)])->save();
        $this->ticket();
        $this->assertSame($this->person->test_login_expires_at->getTimestamp(), TestLoginTicket::sole()->expires_at->getTimestamp());
    }

    public function test_confirmation_page_and_ticket_are_unavailable_by_default(): void
    {
        config(['auth-manager.test_logins.ticket_clients' => []]);
        $this->get('/test-logins/confirm')->assertNotFound();
        $this->postJson('/test-logins/confirm', ['ticket' => str_repeat('x', 43)])->assertForbidden();
    }

    public function test_browser_posts_require_csrf_even_with_a_valid_ticket(): void
    {
        $token = $this->ticket();
        $this->app['env'] = 'production';
        $this->postJson('/test-logins/preview', ['ticket' => $token])->assertStatus(419);
        $this->postJson('/test-logins/confirm', ['ticket' => $token])->assertStatus(419);
        $this->assertGuest();
        $this->assertNull(TestLoginTicket::sole()->used_at);
    }
}
