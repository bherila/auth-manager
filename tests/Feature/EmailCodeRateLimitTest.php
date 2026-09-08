<?php

namespace Tests\Feature;

use App\Models\User;
use BWH\Auth\Models\TwoFactorAttempt;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Tests\TestCase;

class EmailCodeRateLimitTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        Mail::fake();
    }

    public function test_known_unknown_and_disabled_addresses_have_opaque_tokens_and_the_same_throttle_response(): void
    {
        User::factory()->create(['email' => 'known@example.test', 'user_role' => 'user']);
        User::factory()->create(['email' => 'disabled@example.test', 'user_role' => 'user', 'disabled_at' => now()]);
        foreach (['known@example.test', 'unknown@example.test', 'disabled@example.test'] as $email) {
            $response = $this->postJson('/login/email-code', ['email' => $email])->assertOk()->assertJsonPath('success', true);
            $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]{64}$/', $response->json('attempt_token'));
            // A person who mistypes or misses the mail gets a few honest retries within five minutes.
            $this->postJson('/login/email-code', ['email' => strtoupper($email)])->assertOk();
            $this->postJson('/login/email-code', ['email' => $email])->assertOk();
            $this->postJson('/login/email-code', ['email' => strtoupper($email)])->assertTooManyRequests()->assertJsonPath('success', false)->assertHeader('Retry-After');
            $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.20'])->postJson('/login/email-code', ['email' => $email])->assertTooManyRequests();
            Cache::flush();
            $knownAttempts ??= TwoFactorAttempt::count();
        }
        // Only the known, enabled address ever produced a real challenge.
        $this->assertGreaterThanOrEqual(1, $knownAttempts);
        $this->assertSame($knownAttempts, TwoFactorAttempt::count());
    }

    public function test_ip_budget_limits_different_addresses_and_email_budget_crosses_ips(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->postJson('/login/email-code', ['email' => "person{$i}@example.test"])->assertOk();
        }
        $this->postJson('/login/email-code', ['email' => 'next@example.test'])->assertTooManyRequests();
        // A second IP is not blocked by the first IP's budget, but the address budget follows the address.
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])->postJson('/login/email-code', ['email' => 'person0@example.test'])->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.11'])->postJson('/login/email-code', ['email' => 'person0@example.test'])->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.12'])->postJson('/login/email-code', ['email' => 'person0@example.test'])->assertTooManyRequests();
        $this->travel(61)->seconds();
        $this->postJson('/login/email-code', ['email' => 'person0@example.test'])->assertTooManyRequests();
        $this->travel(5)->minutes();
        $this->postJson('/login/email-code', ['email' => 'person0@example.test'])->assertOk();
    }

    public function test_invalid_email_shapes_are_validation_errors(): void
    {
        $this->postJson('/login/email-code', ['email' => ['not-a-string']])->assertUnprocessable();
    }
}
