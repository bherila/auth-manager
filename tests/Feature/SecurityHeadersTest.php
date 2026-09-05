<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Route;
use Tests\TestCase;

final class SecurityHeadersTest extends TestCase
{
    public function test_secure_responses_include_the_security_header_baseline(): void
    {
        $response = $this->get('https://identity.example.test/up');

        $response->assertOk()
            ->assertHeader('Content-Security-Policy', "base-uri 'self'; frame-ancestors 'none'; object-src 'none'")
            ->assertHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=(), payment=(), usb=()')
            ->assertHeader('Referrer-Policy', 'no-referrer')
            ->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('X-Permitted-Cross-Domain-Policies', 'none');
    }

    public function test_hsts_is_not_sent_over_plain_http(): void
    {
        $response = $this->get('http://identity.example.test/up');

        $response->assertOk()
            ->assertHeaderMissing('Strict-Transport-Security')
            ->assertHeader('X-Content-Type-Options', 'nosniff');
    }

    public function test_a_route_specific_policy_is_not_replaced(): void
    {
        Route::get('/security-header-test', static fn () => response('ok')->header(
            'Content-Security-Policy',
            "default-src 'none'",
        ));

        $this->get('https://identity.example.test/security-header-test')
            ->assertOk()
            ->assertHeader('Content-Security-Policy', "default-src 'none'");
    }
}
