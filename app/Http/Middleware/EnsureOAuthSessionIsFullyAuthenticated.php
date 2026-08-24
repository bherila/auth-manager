<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureOAuthSessionIsFullyAuthenticated
{
    public function handle(Request $request, Closure $next): Response
    {
        $prompts = $request->string('prompt')
            ->explode(' ')
            ->map(static fn (string $prompt): string => trim($prompt))
            ->filter();

        abort_if($prompts->contains('none'), 400, 'Silent authorization is not supported.');

        $pendingUserKey = (string) config(
            'bherila-auth.two_factor.session_user_key',
            'bherila_auth_2fa_user_id',
        );

        abort_if($request->session()->has($pendingUserKey), 403, 'Two-factor authentication is not complete.');

        if ($request->user() === null) {
            throw new AuthenticationException(guards: ['web']);
        }

        return $next($request);
    }
}
