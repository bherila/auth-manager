<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Support\ReconciliationClientRegistry;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Laravel\Passport\Bridge\ClientRepository;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateReconciliationClient
{
    public const CLIENT_ATTRIBUTE = 'reconciliation_oauth_client';

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly ReconciliationClientRegistry $registry,
    ) {}

    /** Per-client budgets, by operation: the config key under auth-manager.reconciliation. */
    private const BUDGETS = [
        'status' => 'status_per_client_per_minute',
        'tombstones' => 'tombstones_per_client_per_minute',
    ];

    /**
     * @param  string|null  $operation  `status` or `tombstones`: which per-client budget the request
     *                                  spends once the client is authenticated
     */
    public function handle(Request $request, Closure $next, ?string $operation = null): Response
    {
        if ($operation !== null && ! array_key_exists($operation, self::BUDGETS)) {
            throw new \LogicException("Unknown reconciliation operation [{$operation}].");
        }

        $clientId = $request->getUser();
        $clientSecret = $request->getPassword();

        if (! is_string($clientId)
            || $clientId === ''
            || ! is_string($clientSecret)
            || $clientSecret === ''
            || ! $this->clients->validateClient($clientId, $clientSecret, null)) {
            return $this->unauthorized();
        }

        $client = PassportClient::query()->whereKey($clientId)->where('revoked', false)->first();

        if (! $client instanceof PassportClient || ! $this->registry->isParticipant($client)) {
            return $this->unauthorized();
        }

        $request->attributes->set(self::CLIENT_ATTRIBUTE, $client);

        if ($operation !== null) {
            // Keyed on the authenticated client, so consumers behind one egress IP each have their own
            // budget, and on the operation, so a tombstone backlog never spends status checks.
            $key = 'reconciliation-'.$operation.':client:'.$client->getKey();
            $limit = max(1, (int) config('auth-manager.reconciliation.'.self::BUDGETS[$operation], 1));
            if (RateLimiter::tooManyAttempts($key, $limit)) {
                return $this->tooManyRequests(RateLimiter::availableIn($key));
            }
            RateLimiter::hit($key, 60);
        }

        $response = $next($request);
        $response->headers->set('Cache-Control', 'private, no-store');

        return $response;
    }

    private function tooManyRequests(int $retryAfter): JsonResponse
    {
        return response()->json([
            'message' => 'Too many reconciliation requests for this application. Try again later.',
        ], 429, [
            'Retry-After' => (string) max(1, $retryAfter),
            'Cache-Control' => 'private, no-store',
        ]);
    }

    private function unauthorized(): JsonResponse
    {
        return response()->json([
            'message' => 'Valid relying-application credentials are required.',
        ], 401, [
            'WWW-Authenticate' => 'Basic realm="identity-reconciliation", charset="UTF-8"',
            'Cache-Control' => 'private, no-store',
        ]);
    }
}
