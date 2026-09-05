<?php

namespace Tests\Feature;

use App\Support\AuthManagerProfile;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

class AuthManagerProfileTest extends TestCase
{
    public function test_bherila_is_the_default_profile_and_preserves_legacy_oauth_routes(): void
    {
        $this->assertSame('bherila', config('auth-manager.profile'));
        $this->assertFalse(config('auth-manager.oauth_server'));
        $this->assertTrue(config('bherila-auth.routes.enabled'));
        $this->assertFalse(config('bherila-auth.oauth_server.enabled'));
        $this->assertSame(['identity:read'], array_keys(config('auth-manager.scopes')));
        $this->assertSame([], config('auth-manager.resource_required_scopes'));
        $this->assertNull(Route::getRoutes()->getByName('oauth.metadata.authorization-server'));
        $this->assertNull(Route::getRoutes()->getByName('oauth.register'));
        $this->assertNull(Route::getRoutes()->getByName('oauth.introspect'));

        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.authorizations.deny', 'passport.token'] as $name) {
            $route = Route::getRoutes()->getByName($name);
            $this->assertNotNull($route);
            $this->assertNotContains(EnforceOAuthPkce::class, $route->gatherMiddleware());
            $this->assertNotContains(EnforceOAuthResourceIndicator::class, $route->gatherMiddleware());
        }
    }

    public function test_profiles_have_disjoint_scope_and_resource_policy(): void
    {
        $this->assertSame(['identity:read'], array_keys(AuthManagerProfile::Bherila->scopes()));
        $this->assertSame([], AuthManagerProfile::Bherila->resourceRequiredScopes());
        $this->assertSame(['mcp:use', 'offers:read'], array_keys(AuthManagerProfile::ResourceServer->scopes()));
        $this->assertSame(['mcp:use', 'offers:read'], AuthManagerProfile::ResourceServer->resourceRequiredScopes());
        $this->assertNull(AuthManagerProfile::ResourceServer->defaultIssuer());
        $this->assertNull(AuthManagerProfile::ResourceServer->defaultResource());
    }

    public function test_theme_configuration_is_safe_for_embedding(): void
    {
        $this->assertSame('.bherila.net', config('auth-manager.theme.cookie_domain'));
        $this->assertSame(['bherila.net'], config('auth-manager.theme.allowed_hosts'));
        $this->assertNull(config('session.domain'));

        $rendered = view('layouts.theme-init')->render();
        $this->assertStringContainsString('var cookieDomain = ".bherila.net"', $rendered);
        $this->assertStringContainsString('var allowedHosts = ["bherila.net"]', $rendered);
        $this->assertStringNotContainsString('domain=.bherila.net', $rendered);
    }
}
