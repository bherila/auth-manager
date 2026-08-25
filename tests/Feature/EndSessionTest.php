<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * Signing out at the provider, and returning to the application that asked.
 *
 * The destination is the dangerous part: this host is one people are trained to trust with
 * a password, so an unvalidated return URL would be an open redirect with the worst possible
 * branding behind it. A destination is honoured only when it shares an origin with a redirect
 * URI the named client already registered.
 */
class EndSessionTest extends TestCase
{
    use RefreshDatabase;

    private string $clientId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->clientId = (string) Str::uuid();

        DB::table('oauth_clients')->insert([
            'id' => $this->clientId,
            'name' => 'Finance',
            'secret' => 'secret',
            'redirect_uris' => json_encode(['https://pf.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code']),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function endSession(array $query): TestResponse
    {
        return $this->get('/oauth/end-session?'.http_build_query($query));
    }

    public function test_it_signs_out_and_returns_to_the_requesting_application(): void
    {
        $this->actingAs(User::factory()->create());

        $this->endSession([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => 'https://pf.example.test/',
        ])->assertRedirect('https://pf.example.test/');

        $this->assertGuest();
    }

    /**
     * The whole point of the endpoint: the provider session must actually be gone, or the
     * next authorize request signs the person straight back in and sign-out means nothing.
     */
    public function test_the_provider_session_is_really_ended(): void
    {
        $this->actingAs(User::factory()->create());
        $this->endSession(['client_id' => $this->clientId, 'post_logout_redirect_uri' => 'https://pf.example.test/']);

        $this->assertGuest();
        $this->get('/oauth/authorize')->assertRedirect(route('login'));
    }

    public function test_an_unregistered_destination_is_refused(): void
    {
        $this->actingAs(User::factory()->create());

        $this->endSession([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => 'https://evil.example.test/steal',
        ])->assertRedirect(url('/'));

        $this->assertGuest();
    }

    /**
     * Matching is on origin, so a registered host cannot be used to reach an attacker's by
     * appending one, and a look-alike host is not a match either.
     */
    public function test_a_lookalike_destination_is_refused(): void
    {
        $this->actingAs(User::factory()->create());

        foreach ([
            'https://pf.example.test.evil.test/',
            'http://pf.example.test/',
            'https://pf.example.test:8443/',
            '//evil.example.test',
        ] as $destination) {
            $this->endSession([
                'client_id' => $this->clientId,
                'post_logout_redirect_uri' => $destination,
            ])->assertRedirect(url('/'));
        }
    }

    public function test_an_unknown_client_cannot_name_a_destination(): void
    {
        $this->actingAs(User::factory()->create());

        $this->endSession([
            'client_id' => (string) Str::uuid(),
            'post_logout_redirect_uri' => 'https://pf.example.test/',
        ])->assertRedirect(url('/'));
    }

    public function test_a_revoked_client_cannot_name_a_destination(): void
    {
        DB::table('oauth_clients')->where('id', $this->clientId)->update(['revoked' => true]);
        $this->actingAs(User::factory()->create());

        $this->endSession([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => 'https://pf.example.test/',
        ])->assertRedirect(url('/'));
    }

    /**
     * Signing out when already signed out should land somewhere, not error — a person whose
     * session expired still clicks the button.
     */
    public function test_signing_out_while_already_signed_out_is_not_an_error(): void
    {
        $this->endSession([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => 'https://pf.example.test/',
        ])->assertRedirect('https://pf.example.test/');
    }

    public function test_a_bare_request_falls_back_to_this_service(): void
    {
        $this->actingAs(User::factory()->create());

        $this->endSession([])->assertRedirect(url('/'));
        $this->assertGuest();
    }
}
