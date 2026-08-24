<?php

namespace App\Http\Middleware;

use BWH\Auth\Contracts\AuthAuditLogger;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuditOAuthAuthorization
{
    public function __construct(private readonly AuthAuditLogger $auditLogger) {}

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $user = $request->user();

        if ($user instanceof Authenticatable && $this->issuedAuthorizationCode($response)) {
            $this->auditLogger->loginSucceeded($request, $user, 'oauth_authorize');
        }

        return $response;
    }

    private function issuedAuthorizationCode(Response $response): bool
    {
        $location = $response->headers->get('Location');

        if (! is_string($location)) {
            return false;
        }

        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        return is_string($query['code'] ?? null) && $query['code'] !== '';
    }
}
