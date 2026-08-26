<?php

namespace Tests\Feature;

use App\Http\Middleware\RequireOAuthClientGrant;
use App\Models\User;
use App\OAuth\GrantAwareAccessTokenRepository;
use App\OAuth\GrantAwareAuthCodeRepository;
use App\OAuth\GrantAwareRefreshTokenRepository;
use App\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

class OAuthClientGrantTest extends TestCase
{
    use RefreshDatabase;

    public function test_authorization_is_refused_with_the_application_name_without_a_grant(): void
    {
        $this->withoutVite();
        config()->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $user = User::factory()->create(['user_role' => 'user']);
        $clientId = $this->client('Example Application');

        $this->actingAs($user)
            ->get('/oauth/authorize?client_id='.$clientId)
            ->assertForbidden()
            ->assertSee('Access to Example Application is unavailable');
    }

    public function test_authorization_middleware_allows_a_granted_subject_to_continue(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $clientId = $this->client('Example Application');
        $grants = app(OAuthClientGrantService::class);
        $grants->grant((string) $user->getKey(), $clientId);
        $request = Request::create('/oauth/authorize', 'GET', ['client_id' => $clientId]);
        $request->setUserResolver(fn (): User => $user);

        $response = app(RequireOAuthClientGrant::class)->handle(
            $request,
            fn (): Response => new Response('continued', 200),
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('continued', $response->getContent());
    }

    public function test_removing_a_grant_revokes_the_pairs_access_and_refresh_tokens(): void
    {
        $user = User::factory()->create();
        $clientId = $this->client('Example Application');
        $otherClientId = $this->client('Other Application');
        $grants = app(OAuthClientGrantService::class);
        $grants->grant((string) $user->getKey(), $clientId);
        $accessTokenId = $this->accessToken((int) $user->getKey(), $clientId);
        $otherAccessTokenId = $this->accessToken((int) $user->getKey(), $otherClientId);
        $this->refreshToken($accessTokenId);
        $this->refreshToken($otherAccessTokenId);

        $grants->revoke((string) $user->getKey(), $clientId);

        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => (string) $user->getKey(),
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['access_token_id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $otherAccessTokenId, 'revoked' => false]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['access_token_id' => $otherAccessTokenId, 'revoked' => false]);
    }

    public function test_code_exchange_and_refresh_repositories_recheck_the_current_grant(): void
    {
        $user = User::factory()->create();
        $clientId = $this->client('Example Application');
        $grants = app(OAuthClientGrantService::class);
        $grants->grant((string) $user->getKey(), $clientId);
        $accessTokenId = $this->accessToken((int) $user->getKey(), $clientId);
        $refreshTokenId = $this->refreshToken($accessTokenId);
        $authCodeId = str_repeat('a', 80);
        DB::table('oauth_auth_codes')->insert([
            'id' => $authCodeId,
            'user_id' => $user->getKey(),
            'client_id' => $clientId,
            'scopes' => '[]',
            'revoked' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        $authCodes = app(AuthCodeRepository::class);
        $accessTokens = app(AccessTokenRepository::class);
        $refreshTokens = app(RefreshTokenRepository::class);
        $this->assertInstanceOf(GrantAwareAuthCodeRepository::class, $authCodes);
        $this->assertInstanceOf(GrantAwareAccessTokenRepository::class, $accessTokens);
        $this->assertInstanceOf(GrantAwareRefreshTokenRepository::class, $refreshTokens);
        $this->assertFalse($authCodes->isAuthCodeRevoked($authCodeId));
        $this->assertFalse($accessTokens->isAccessTokenRevoked($accessTokenId));
        $this->assertFalse($refreshTokens->isRefreshTokenRevoked($refreshTokenId));

        DB::table('oauth_client_grants')
            ->where('subject', (string) $user->getKey())
            ->where('oauth_client_id', $clientId)
            ->delete();

        $this->assertTrue($authCodes->isAuthCodeRevoked($authCodeId));
        $this->assertTrue($accessTokens->isAccessTokenRevoked($accessTokenId));
        $this->assertTrue($refreshTokens->isRefreshTokenRevoked($refreshTokenId));
    }

    public function test_oauth_credentials_are_rejected_when_the_provider_account_is_disabled(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $clientId = $this->client('Example Application');
        $grants = app(OAuthClientGrantService::class);
        $grants->grant((string) $user->getKey(), $clientId);
        $accessTokenId = $this->accessToken((int) $user->getKey(), $clientId);
        $refreshTokenId = $this->refreshToken($accessTokenId);
        $authCodeId = str_repeat('b', 80);
        DB::table('oauth_auth_codes')->insert([
            'id' => $authCodeId,
            'user_id' => $user->getKey(),
            'client_id' => $clientId,
            'scopes' => '[]',
            'revoked' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        $user->update(['disabled_at' => now()]);

        $this->assertTrue(app(AuthCodeRepository::class)->isAuthCodeRevoked($authCodeId));
        $this->assertTrue(app(AccessTokenRepository::class)->isAccessTokenRevoked($accessTokenId));
        $this->assertTrue(app(RefreshTokenRepository::class)->isRefreshTokenRevoked($refreshTokenId));
        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => $user->getKey(),
            'oauth_client_id' => $clientId,
        ]);
    }

    public function test_deleting_a_client_invalidates_its_existing_subject_access_token(): void
    {
        $user = User::factory()->create();
        $clientId = $this->client('Example Application');
        $grants = app(OAuthClientGrantService::class);
        $grants->grant((string) $user->getKey(), $clientId);
        $accessTokenId = $this->accessToken((int) $user->getKey(), $clientId);
        $accessTokens = app(AccessTokenRepository::class);
        $this->assertFalse($accessTokens->isAccessTokenRevoked($accessTokenId));

        DB::table('oauth_clients')->where('id', $clientId)->delete();

        $this->assertDatabaseHas('oauth_access_tokens', [
            'id' => $accessTokenId,
            'revoked' => false,
        ]);
        $this->assertTrue($accessTokens->isAccessTokenRevoked($accessTokenId));
    }

    private function client(string $name): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => $name,
            'secret' => 'secret',
            'redirect_uris' => json_encode(['https://app.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code', 'refresh_token']),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    private function accessToken(int $userId, string $clientId): string
    {
        $id = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $id,
            'user_id' => $userId,
            'client_id' => $clientId,
            'name' => null,
            'scopes' => '[]',
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }

    private function refreshToken(string $accessTokenId): string
    {
        $id = Str::random(80);
        DB::table('oauth_refresh_tokens')->insert([
            'id' => $id,
            'access_token_id' => $accessTokenId,
            'revoked' => false,
            'expires_at' => now()->addDay(),
        ]);

        return $id;
    }
}
