<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The passkey ceremony spans two requests: the browser asks for a challenge, the
 * authenticator signs it, and the signature is posted back. The challenge is held in the
 * session in between. If it does not survive that gap the second request reports that no
 * ceremony was started, which reads as a bug in the passkey code rather than in whatever
 * actually discarded the session.
 */
class PasskeyChallengePersistenceTest extends TestCase
{
    use RefreshDatabase;

    private const SESSION_KEY = 'bherila_auth_webauthn_login_options';

    public function test_requesting_a_challenge_stores_it_in_the_session(): void
    {
        $response = $this->postJson('/api/passkeys/auth/options');

        $response->assertOk();
        $response->assertJsonStructure(['challenge', 'rpId']);

        $this->assertNotNull(
            session(self::SESSION_KEY),
            'The challenge was not retained in the session, so the signature step will report that no ceremony is pending.'
        );
    }

    public function test_the_challenge_survives_into_a_following_request(): void
    {
        $this->postJson('/api/passkeys/auth/options')->assertOk();

        // A second request on the same session must still see the pending challenge.
        $this->get('/login')->assertOk();

        $this->assertNotNull(session(self::SESSION_KEY));
    }

    public function test_the_challenge_is_bound_to_the_configured_relying_party(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);

        $this->postJson('http://id.example.com/api/passkeys/auth/options')
            ->assertOk()
            ->assertJsonPath('rpId', 'example.com');
    }

    public function test_a_host_the_relying_party_cannot_cover_falls_back_rather_than_issuing_an_unusable_challenge(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.com']);

        // Local development against a production-shaped configuration must still work.
        $this->postJson('http://localhost/api/passkeys/auth/options')
            ->assertOk()
            ->assertJsonPath('rpId', 'localhost');
    }
}
