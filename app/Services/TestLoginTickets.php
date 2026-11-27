<?php

namespace BWH\AuthManager\Services;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\TestLoginTicket;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\Mount;
use BWH\AuthManager\Support\StaticApplicationClients;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use SensitiveParameter;

/** A synthetic password presentation, never an ordinary-user authentication bypass. */
final class TestLoginTickets
{
    public function __construct(private readonly StaticApplicationClients $clients, private readonly OAuthClientGrantService $grants) {}

    public function clientEnabled(PassportClient $client): bool
    {
        return $this->clients->eligible($client) && $client->confidential()
            && in_array((string) $client->getKey(), config('auth-manager.test_logins.ticket_clients', []), true)
            && RegisteredApplication::query()->where('enabled', true)->whereHas('clients', fn ($query) => $query->whereKey($client->getKey()))->exists();
    }

    /** @param array<string, string> $authorization
     * @return array{token: string, expires_at: string}
     */
    public function issue(PassportClient $client, string $subject, #[SensitiveParameter] string $password, array $authorization): array
    {
        $uri = $this->authorizationUri($client, $authorization);

        return DB::transaction(function () use ($client, $subject, $password, $uri): array {
            $client = PassportClient::query()->lockForUpdate()->find($client->getKey());
            $user = User::query()->whereProviderSubject($subject)->lockForUpdate()->first();
            abort_unless($client instanceof PassportClient && $user instanceof User
                && $user->providerSubject() === $subject && $this->eligible($client, $user)
                && Hash::check($password, $user->password), 403, 'Synthetic sign-in is unavailable.');
            $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $expires = now('UTC')->addSeconds(60)->min($user->test_login_expires_at);
            TestLoginTicket::create([
                'token_hash' => hash('sha256', $token), 'client_id' => $client->getKey(), 'user_id' => $user->getKey(),
                'credential_version' => (int) $user->credential_version, 'authorization_uri' => $uri, 'expires_at' => $expires,
            ]);

            return ['token' => $token, 'expires_at' => $expires->toIso8601String()];
        });
    }

    /** @return array{ticket: TestLoginTicket, user: User, client: PassportClient} */
    public function inspect(#[SensitiveParameter] string $token, bool $consume = false): array
    {
        abort_unless(preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $token) === 1, 403, 'Synthetic sign-in has expired.');

        return DB::transaction(function () use ($token, $consume): array {
            $ticket = TestLoginTicket::query()->where('token_hash', hash('sha256', $token))->lockForUpdate()->first();
            abort_unless($ticket instanceof TestLoginTicket && $ticket->used_at === null && $ticket->expires_at->isFuture(), 403, 'Synthetic sign-in has expired.');
            $client = PassportClient::query()->lockForUpdate()->find($ticket->client_id);
            $user = User::query()->lockForUpdate()->find($ticket->user_id);
            abort_unless($client instanceof PassportClient && $user instanceof User && $this->eligible($client, $user)
                && (int) $user->credential_version === $ticket->credential_version, 403, 'Synthetic sign-in is unavailable.');
            // Recheck the callback after issuance, including operator changes to client metadata.
            parse_str((string) parse_url($ticket->authorization_uri, PHP_URL_QUERY), $authorization);
            abort_unless($this->authorizationUri($client, $authorization) === $ticket->authorization_uri, 403);
            if ($consume) {
                $ticket->update(['used_at' => now('UTC')]);
            }

            return compact('ticket', 'user', 'client');
        });
    }

    private function eligible(PassportClient $client, User $user): bool
    {
        return $this->clientEnabled($client) && $user->isTestLogin() && ! $user->hasRole('admin') && $user->canLogin()
            && $this->grants->allows((string) $user->getKey(), (string) $client->getKey(), true);
    }

    /** @param array<string, mixed> $parameters */
    private function authorizationUri(PassportClient $client, array $parameters): string
    {
        if (array_key_exists('scope', $parameters) && ($parameters['scope'] === null || $parameters['scope'] === '')) {
            unset($parameters['scope']);
        }
        $required = ['client_id', 'redirect_uri', 'response_type', 'state', 'code_challenge', 'code_challenge_method'];
        $allowed = [...$required, 'scope'];
        abort_unless($this->clientEnabled($client) && array_diff($required, array_keys($parameters)) === []
            && array_diff(array_keys($parameters), $allowed) === [], 403);
        foreach ($parameters as $key => $value) {
            abort_unless(is_string($value) && strlen($value) <= 2048
                && ! preg_match($key === 'scope' ? '/[\x00-\x1f\x7f]/' : '/[\x00-\x20\x7f]/', $value), 403);
        }
        abort_unless($parameters['client_id'] === (string) $client->getKey()
            && in_array($parameters['redirect_uri'], $client->redirect_uris, true)
            && $parameters['response_type'] === 'code' && $parameters['code_challenge_method'] === 'S256'
            && preg_match('/\A[A-Za-z0-9]{40,128}\z/D', $parameters['state']) === 1
            && preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $parameters['code_challenge']) === 1, 403);

        return Mount::path('/oauth/authorize').'?'.http_build_query($parameters);
    }
}
