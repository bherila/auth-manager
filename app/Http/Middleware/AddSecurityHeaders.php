<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class AddSecurityHeaders
{
    /**
     * Add a conservative baseline without replacing a route-specific policy.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $this->setIfMissing($response, 'Content-Security-Policy', "base-uri 'self'; frame-ancestors 'none'; object-src 'none'");
        $this->setIfMissing($response, 'Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()');
        $this->setIfMissing($response, 'Referrer-Policy', 'no-referrer');
        $this->setIfMissing($response, 'X-Content-Type-Options', 'nosniff');
        $this->setIfMissing($response, 'X-Frame-Options', 'DENY');
        $this->setIfMissing($response, 'X-Permitted-Cross-Domain-Policies', 'none');

        if ($request->isSecure()) {
            $this->setIfMissing($response, 'Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        return $response;
    }

    private function setIfMissing(Response $response, string $name, string $value): void
    {
        if (! $response->headers->has($name)) {
            $response->headers->set($name, $value);
        }
    }
}
