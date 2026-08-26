<?php

namespace App\Http\Middleware;

use App\Models\PassportClient;
use App\Support\ReconciliationClientRegistry;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\Bridge\ClientRepository;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateReconciliationClient
{
    public const CLIENT_ATTRIBUTE = 'reconciliation_oauth_client';

    public function __construct(
        private readonly ClientRepository $clients,
        private readonly ReconciliationClientRegistry $registry,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
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

        $response = $next($request);
        $response->headers->set('Cache-Control', 'private, no-store');

        return $response;
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
