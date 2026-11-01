<?php

namespace Tests\Embedded;

use BWH\AuthManager\Support\AuthManagerProfile;
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
}
