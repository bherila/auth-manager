<?php

namespace App\Services\DelegatedAccess;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Support\AuthManagerProfile;
use App\Support\StaticApplicationClients;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Throwable;

final class DelegatedAccessTransport
{
    public function __construct(private readonly ActorAssertion $assertions, private readonly DelegatedContract $contract, private readonly TransportClock $clock) {}

    public function send(Request $request, string $application, array $operation): array
    {
        if (! config('delegated-access.enabled', false)) {
            throw new DelegatedAccessException('integration_disabled');
        }
        $payload = $this->contract->request($application, $operation);
        $write = $payload['operation'] === 'update';
        $actor = $this->actor($request, $application, $write);
        $configuration = config('delegated-access');
        $endpoint = $configuration['applications'][$application]['endpoint'] ?? null;
        $issuer = $configuration['issuer'] ?? null;
        $keyPath = $configuration['private_key_path'] ?? null;
        $keyId = $configuration['key_id'] ?? null;
        try {
            AuthManagerProfile::validatedAbsoluteUrl($endpoint, 'Delegated endpoint');
            $issuer = AuthManagerProfile::validatedIssuerUrl($issuer, 'Delegated issuer');
            if (parse_url($endpoint, PHP_URL_SCHEME) !== 'https' || parse_url($issuer, PHP_URL_SCHEME) !== 'https'
                || ! is_string($keyPath) || ! is_readable($keyPath) || ! is_string($keyId) || $keyId === '') {
                throw new DelegatedAccessException('invalid_configuration');
            }
            $body = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (strlen($body) > DelegatedContract::MAX_REQUEST_BYTES) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
            $key = file_get_contents($keyPath);
            if (! is_string($key) || $key === '') {
                throw new DelegatedAccessException('invalid_configuration');
            }
            $correlation = bin2hex(random_bytes(32));
            $assertion = $this->assertions->issue($issuer, (string) $actor->id, $endpoint, $application, $body, $keyId, $key, $correlation);
        } catch (DelegatedAccessException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new DelegatedAccessException('invalid_configuration');
        }

        if ($write) {
            $this->audit($actor, $application, $payload['subject'], $correlation, 'attempt');
        }
        try {
            $result = $this->exchange($endpoint, $assertion, $body, $application, $payload, $write);
        } catch (Throwable $failure) {
            $exception = $failure instanceof DelegatedAccessException ? $failure : new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
            if ($write) {
                $this->audit($actor, $application, $payload['subject'], $correlation, $exception->outcome);
            }
            throw $exception;
        }
        if ($write) {
            $this->audit($actor, $application, $payload['subject'], $correlation, 'succeeded');
        }

        return $result;
    }

    private function audit(User $actor, string $application, string $target, string $correlation, string $outcome): void
    {
        try {
            $entry = AuthAuditLog::create([
                'user_id' => $actor->id, 'acting_user_id' => $actor->id,
                'event' => $outcome === 'attempt' ? 'delegated_access_update_attempt' : 'delegated_access_update_result',
                'auth_method' => 'delegated', 'succeeded' => $outcome === 'succeeded',
                'metadata' => ['application' => $application, 'target' => $target, 'operation' => 'update',
                    'outcome' => $outcome, 'correlation' => $correlation],
            ]);
            if (! $entry->exists) {
                throw new DelegatedAccessException('audit_unavailable');
            }
        } catch (Throwable) {
            // A missing attempt record prevents transmission. A failed result record
            // leaves a durable attempt and must never turn a remote write into success.
            throw new DelegatedAccessException($outcome === 'attempt' ? 'audit_unavailable' : 'unknown_outcome');
        }
    }

    private function exchange(string $endpoint, #[\SensitiveParameter] string $assertion, string $body, string $application, array $payload, bool $write): array
    {
        $deadline = $this->clock->now() + 10;
        try {
            // Never retry writes or follow redirects. Read at most the contract bound,
            // including chunked responses, without buffering an unbounded response.
            $response = Http::connectTimeout(3)->timeout(10)->withoutRedirecting()
                ->withOptions(['stream' => true, 'read_timeout' => 1])
                ->withHeaders(['Authorization' => 'Bearer '.$assertion, 'Accept' => 'application/json'])
                ->withBody($body, 'application/json')->post($endpoint);
        } catch (Throwable) {
            throw new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
        }
        $stream = $response->toPsrResponse()->getBody();
        try {
            if ($this->clock->now() >= $deadline) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'invalid_response');
            }
            if (in_array($response->status(), [403, 404, 409, 422], true)) {
                throw new DelegatedAccessException(match ($response->status()) {
                    403, 404 => 'not_authorized',
                    409 => 'revision_conflict',
                    422 => 'invalid_request',
                }, $response->status());
            }
            if (! $response->successful()) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
            }
            try {
                $bytes = '';
                while (! $stream->eof() && strlen($bytes) <= DelegatedContract::MAX_RESPONSE_BYTES) {
                    if ($this->clock->now() >= $deadline) {
                        throw new DelegatedAccessException('invalid_response');
                    }
                    $chunk = $stream->read(min(8192, DelegatedContract::MAX_RESPONSE_BYTES + 1 - strlen($bytes)));
                    if ($this->clock->now() >= $deadline || ($chunk === '' && ! $stream->eof())) {
                        throw new DelegatedAccessException('invalid_response');
                    }
                    $bytes .= $chunk;
                }
                if ($this->clock->now() >= $deadline || strlen($bytes) > DelegatedContract::MAX_RESPONSE_BYTES) {
                    throw new DelegatedAccessException('invalid_response');
                }

                return $this->contract->response(json_decode($bytes, true, 64, JSON_THROW_ON_ERROR), $application, $payload['operation'], $payload['subject'] ?? null);
            } catch (Throwable) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'invalid_response');
            }
        } finally {
            $stream->close();
        }
    }

    private function actor(Request $request, string $application, bool $write): User
    {
        $sessionUser = $request->user();
        $actor = $sessionUser instanceof User ? User::query()->find($sessionUser->id) : null;
        if (! $actor instanceof User || ! $actor->canLogin() || ! $request->hasSession()
            || $request->session()->get(EnsureCredentialVersion::SESSION_KEY) !== (int) $actor->credential_version) {
            throw new DelegatedAccessException('not_authenticated', 401);
        }
        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->with('clients')->first();
        $staticClients = new StaticApplicationClients;
        if ($registration === null || ! $registration->clients->contains(fn (PassportClient $client): bool => $staticClients->eligible($client)
            && DB::table('oauth_client_grants')->where('subject', $actor->id)->where('oauth_client_id', $client->id)->exists())) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        if ($write) {
            $proof = $request->session()->get(RequireRecentPasskeyAuthentication::SESSION_KEY);
            $now = now()->getTimestamp();
            if (! config('delegated-access.writes_enabled', false) || ! is_array($proof)
                || ($proof['user_id'] ?? null) !== (string) $actor->id
                || ! is_int($proof['authenticated_at'] ?? null)
                || $proof['authenticated_at'] > $now || $proof['authenticated_at'] < $now - 300) {
                throw new DelegatedAccessException('recent_confirmation_required', 403);
            }
        }

        return $actor;
    }
}
