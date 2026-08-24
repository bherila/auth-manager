<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureOAuthSessionIsFullyAuthenticated;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class OAuthAuthorizationGuardTest extends TestCase
{
    private function requestWith(array $query = [], array $session = []): Request
    {
        $request = Request::create('/oauth/authorize', 'GET', $query);
        $store = new Store('test', new ArraySessionHandler(120));
        foreach ($session as $key => $value) {
            $store->put($key, $value);
        }
        $request->setLaravelSession($store);

        return $request;
    }

    public function test_silent_authorization_is_refused(): void
    {
        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Silent authorization is not supported.');

        (new EnsureOAuthSessionIsFullyAuthenticated)->handle(
            $this->requestWith(['prompt' => 'none']),
            fn (): Response => new Response,
        );
    }

    public function test_silent_authorization_is_refused_when_combined_with_other_prompts(): void
    {
        $this->expectException(HttpException::class);

        (new EnsureOAuthSessionIsFullyAuthenticated)->handle(
            $this->requestWith(['prompt' => 'login none']),
            fn (): Response => new Response,
        );
    }

    public function test_a_session_pending_second_factor_cannot_authorize(): void
    {
        $pendingKey = (string) config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id');

        $this->expectException(HttpException::class);
        $this->expectExceptionMessage('Two-factor authentication is not complete.');

        (new EnsureOAuthSessionIsFullyAuthenticated)->handle(
            $this->requestWith([], [$pendingKey => 7]),
            fn (): Response => new Response,
        );
    }

    public function test_an_unauthenticated_session_is_rejected(): void
    {
        $this->expectException(AuthenticationException::class);

        (new EnsureOAuthSessionIsFullyAuthenticated)->handle(
            $this->requestWith(),
            fn (): Response => new Response,
        );
    }
}
