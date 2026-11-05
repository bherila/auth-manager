<?php

namespace Tests\Embedded;

use BWH\Auth\Http\Middleware\AppendOAuthAuthorizationResponseIssuer;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Support\AuthManagerProfile;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use InvalidArgumentException;

/** The resource profile embedded: RFC 8414 metadata for an issuer with a path. */
class EmbeddedResourceProfileTest extends EmbeddedTestCase
{
    protected array $environment = [
        'AUTH_MANAGER_PROFILE' => 'resource',
        'AUTH_MANAGER_OAUTH_RESOURCE' => 'https://app.example.test/api/mcp',
    ];

    public function test_metadata_is_published_for_the_prefixed_issuer(): void
    {
        $expected = [
            'issuer' => self::HOST.'/auth',
            'authorization_endpoint' => self::HOST.'/auth/oauth/authorize',
            'token_endpoint' => self::HOST.'/auth/oauth/token',
            'registration_endpoint' => self::HOST.'/auth/oauth/register',
        ];

        // RFC 8414 section 3: the well-known path, then the issuer's path.
        $metadata = $this->getJson('/.well-known/oauth-authorization-server/auth')->assertOk();
        foreach ($expected as $key => $value) {
            $metadata->assertJsonPath($key, $value);
        }
        $this->assertContains('S256', $metadata->json('code_challenge_methods_supported'));
        $metadata->assertJsonPath('authorization_response_iss_parameter_supported', true);

        // The same document below the prefix, for clients that look there.
        $this->getJson('/auth/.well-known/oauth-authorization-server')->assertOk()->assertJsonPath('issuer', self::HOST.'/auth');

        // The host's own document at the bare well-known path is untouched.
        $this->getJson('/.well-known/oauth-authorization-server')->assertOk()->assertExactJson(['issuer' => 'host']);
    }

    public function test_the_relying_party_flow_completes_and_pkce_is_required(): void
    {
        [$user, $client, $secret] = $this->grantedClient('correct horse battery staple');

        $authorization = $this->authorizeThroughBrowser($client, 'correct horse battery staple');
        $tokens = $this->exchange($client, $secret, $authorization['code'], $authorization['verifier']);
        $this->freshRequest()->withToken((string) $tokens['access_token'])->getJson('/auth/api/oauth/user')
            ->assertOk()->assertJsonPath('sub', (string) $user->getKey());

        $this->freshRequest()->withCookie('auth_manager_session', $authorization['session'])
            ->get('/auth/oauth/authorize?'.http_build_query([
                'client_id' => (string) $client->getKey(),
                'redirect_uri' => self::CALLBACK,
                'response_type' => 'code',
                'scope' => 'identity:read',
                'state' => 'state-value',
            ]))
            ->assertStatus(400)
            ->assertJsonPath('error_description', 'Authorization requests require S256 PKCE.');
    }

    public function test_an_embedded_issuer_must_be_the_mount_url(): void
    {
        $this->assertSame(self::HOST.'/auth', AuthManagerProfile::validatedIssuerUrl(self::HOST.'/auth/', 'ISSUER', '/auth'));

        $this->expectException(InvalidArgumentException::class);
        AuthManagerProfile::validatedIssuerUrl(self::HOST.'/elsewhere', 'ISSUER', '/auth');
    }

    public function test_authorization_responses_use_the_embedded_path_issuer_and_all_routes_install_the_middleware(): void
    {
        [, $client] = $this->grantedClient('correct horse battery staple');
        $authorization = $this->authorizeThroughBrowser($client, 'correct horse battery staple');
        $response = $this->freshRequest()->withCookie('auth_manager_session', $authorization['session'])
            ->get('/auth/oauth/authorize?'.http_build_query([
                'client_id' => (string) $client->getKey(), 'redirect_uri' => self::CALLBACK,
                'response_type' => 'code', 'scope' => 'identity:read', 'state' => 'embedded-state',
                'code_challenge' => str_repeat('a', 43), 'code_challenge_method' => 'S256',
            ]))->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame(self::HOST.'/auth', $query['iss'] ?? null);
        $this->assertSame('embedded-state', $query['state'] ?? null);
        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.authorizations.deny'] as $name) {
            $this->assertContains(AppendOAuthAuthorizationResponseIssuer::class, Route::getRoutes()->getByName($name)?->gatherMiddleware() ?? []);
        }
    }

    public function test_fragment_error_decoration_uses_provider_context_and_leaves_internal_redirects_untouched(): void
    {
        app(EmbeddedContext::class)->run(function (): void {
            $middleware = new AppendOAuthAuthorizationResponseIssuer;
            $response = $middleware->handle(Request::create('/auth/oauth/authorize', 'DELETE'), static function () {
                throw new HttpResponseException(redirect()->away(self::CALLBACK.'#error=access_denied&state=fragment-state'));
            });
            parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_FRAGMENT), $fragment);
            $this->assertSame(['error' => 'access_denied', 'state' => 'fragment-state', 'iss' => self::HOST.'/auth'], $fragment);

            $login = redirect()->route('auth-manager.login');
            $this->assertSame($login, $middleware->handle(Request::create('/auth/oauth/authorize'), static fn () => $login));
            $this->assertSame(self::HOST.'/auth/login', $login->getTargetUrl());
        });
    }
}
