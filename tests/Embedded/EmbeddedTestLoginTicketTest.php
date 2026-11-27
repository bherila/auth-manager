<?php

namespace Tests\Embedded;

use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use BWH\AuthManager\Services\TestLoginTickets;
use Laravel\Passport\ClientRepository;

class EmbeddedTestLoginTicketTest extends EmbeddedTestCase
{
    public function test_ticket_confirmation_and_authorization_use_provider_prefix_and_separate_session(): void
    {
        [$client, $ticket] = app(EmbeddedContext::class)->run(function (): array {
            $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Synthetic Application', [self::CALLBACK]);
            $client = $client->fresh();
            RegisteredApplication::create(['key' => 'synthetic', 'name' => 'Synthetic', 'launch_url' => self::HOST, 'enabled' => true])->clients()->attach($client->id);
            config(['auth-manager.test_logins.ticket_clients' => [(string) $client->id]]);
            $user = User::factory()->make(['email' => 'synthetic@example.test', 'user_role' => 'user', 'password' => 'synthetic-password']);
            $user->forceFill(['is_test_login' => true, 'test_login_expires_at' => now('UTC')->addHour()])->save();
            app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
            $ticket = app(TestLoginTickets::class)->issue($client, $user->providerSubject(), 'synthetic-password', [
                'client_id' => (string) $client->id, 'redirect_uri' => self::CALLBACK, 'response_type' => 'code',
                'state' => str_repeat('a', 40), 'code_challenge' => str_repeat('b', 43), 'code_challenge_method' => 'S256',
            ]);

            return [$client, $ticket];
        });
        $this->get('/auth/test-logins/confirm')->assertOk()->assertSee('/auth/test-logins/preview', false);
        $this->postJson('/auth/test-logins/preview', ['ticket' => $ticket['token']])->assertOk()->assertJsonPath('application', $client->name);
        $this->postJson('/auth/test-logins/confirm', ['ticket' => $ticket['token']])->assertOk()->assertJsonPath('redirect_uri', fn ($uri) => str_starts_with($uri, '/auth/oauth/authorize?'));
        $this->get('/')->assertOk()->assertSee('host home');
        $this->postJson('/auth/test-logins/confirm', ['ticket' => $ticket['token']])->assertForbidden();
    }
}
