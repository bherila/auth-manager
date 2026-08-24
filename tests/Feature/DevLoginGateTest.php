<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The developer login routes authenticate as an arbitrary account without a
 * credential, so their gate is the only thing between a visitor and any user's
 * session. It requires two independent conditions — the `local` environment AND
 * a loopback source address — because a single misconfigured value must not be
 * enough to turn them into a remote authentication bypass.
 */
class DevLoginGateTest extends TestCase
{
    use RefreshDatabase;

    public function test_dev_login_is_rejected_outside_the_local_environment(): void
    {
        config(['app.env' => 'production']);

        $user = User::factory()->create(['user_role' => 'user']);

        $this->post('/login/dev', ['email' => $user->email])->assertForbidden();
        $this->assertGuest();
    }

    public function test_dev_login_is_rejected_from_a_non_loopback_address(): void
    {
        config(['app.env' => 'local']);

        $user = User::factory()->create(['user_role' => 'user']);

        $this->post('/login/dev', ['email' => $user->email], ['REMOTE_ADDR' => '203.0.113.10'])
            ->assertForbidden();
        $this->assertGuest();
    }

    public function test_dev_login_by_id_is_rejected_outside_the_local_environment(): void
    {
        config(['app.env' => 'production']);

        $user = User::factory()->create(['user_role' => 'user']);

        $this->post('/login/dev-by-id', ['user_id' => $user->id])->assertForbidden();
        $this->assertGuest();
    }

    public function test_a_disabled_account_cannot_use_dev_login_even_locally(): void
    {
        config(['app.env' => 'local']);

        $user = User::factory()->create(['user_role' => 'pending']);

        $this->post('/login/dev', ['email' => $user->email])
            ->assertSessionHasErrors('email');
        $this->assertGuest();
    }
}
