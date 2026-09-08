<?php

namespace Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

class TrustedProxiesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Route::get('/whoami', fn (Request $request) => response()->json(['ip' => $request->ip(), 'secure' => $request->isSecure()]));
    }

    public function test_cloudflare_edges_may_forward_the_client_address_by_default(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 104.16.1.2', 'HTTP_X_FORWARDED_PROTO' => 'https'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '198.51.100.7')->assertJsonPath('secure', true);
        $this->withServerVariables(['REMOTE_ADDR' => '2606:4700::1234', 'HTTP_X_FORWARDED_FOR' => '2001:db8::9'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '2001:db8::9');
    }

    public function test_direct_connections_cannot_spoof_the_client_address(): void
    {
        // The origin is reachable without Cloudflare, so a forwarded header from anywhere else is ignored.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7'])
            ->getJson('/whoami')->assertOk()->assertJsonPath('ip', '203.0.113.5');
        $this->withServerVariables(['REMOTE_ADDR' => '104.16.1.2', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7', 'HTTP_X_FORWARDED_HOST' => 'evil.example.test'])
            ->getJson('/whoami')->assertOk()->assertHeaderMissing('X-Forwarded-Host');
        $this->assertSame('localhost', request()->getHost());
    }

    public function test_rate_limits_key_on_the_forwarded_client_behind_cloudflare(): void
    {
        Route::post('/limited', fn () => response()->json(['ok' => true]))->middleware('throttle:2,1');
        foreach (['198.51.100.7', '198.51.100.7', '198.51.100.8'] as $client) {
            $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => $client])->postJson('/limited')->assertOk();
        }
        $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7'])->postJson('/limited')->assertTooManyRequests();
        $this->withServerVariables(['REMOTE_ADDR' => '172.64.9.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.8'])->postJson('/limited')->assertOk();
    }
}
