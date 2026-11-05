<?php

namespace Tests\Embedded;

use BWH\Auth\Models\TwoFactorAttempt;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Services\TrustedDevices;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\HttpFoundation\Cookie;

/** Trusted browsers under an embedded mount (auth-manager#114). */
final class EmbeddedTrustedDevicesTest extends EmbeddedTestCase
{
    private const PASSWORD = 'correct horse battery staple';

    protected array $environment = [
        'AUTH_MANAGER_REQUIRE_CODE_AFTER_PASSWORD' => 'true',
        'AUTH_MANAGER_ALLOW_TRUSTED_DEVICES' => 'true',
    ];

    public function test_a_browser_confirmed_below_the_prefix_skips_the_code_and_pruning_reads_the_provider_tables(): void
    {
        Mail::fake();
        [$user] = $this->grantedClient(self::PASSWORD);
        $credentials = ['email' => $user->email, 'password' => self::PASSWORD];

        $this->post('/auth/login', $credentials)->assertRedirect();
        $attempt = app(EmbeddedContext::class)->run(static fn () => TwoFactorAttempt::query()->latest('id')->firstOrFail());
        $response = $this->postJson('/auth/api/auth/two-factor/verify', [
            'attempt_token' => $attempt->token,
            'code' => $attempt->code,
            'trust_device' => true,
        ])->assertOk();

        // A `__Host-` cookie has to sit on the root path, even with the provider mounted below it.
        $raw = $response->getCookie(TrustedDevices::COOKIE, false);
        $this->assertInstanceOf(Cookie::class, $raw);
        $this->assertSame('/', $raw->getPath());
        $this->assertNull($raw->getDomain());
        $token = (string) $response->getCookie(TrustedDevices::COOKIE)?->getValue();

        session()->flush();
        Auth::forgetGuards();
        Mail::fake();
        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/auth/login', $credentials)->assertRedirect();

        Mail::assertNothingSent();

        $this->assertSame(0, app(EmbeddedContext::class)->run(static fn () => TrustedDevice::pruneUnusable()));
        $this->assertSame(1, app(EmbeddedContext::class)->run(static fn () => TrustedDevice::query()->count()));
    }
}
