<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class PasswordMinimumTest extends TestCase
{
    use RefreshDatabase;

    public function test_eight_character_admin_passwords_obey_instance_policy_and_confirmation(): void
    {
        config(['auth-manager.password_min_length' => 8]);
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create();
        $this->actingAs($admin);
        $url = "/api/admin/users/{$target->id}/password";
        foreach (['1234567', '12345678'] as $password) {
            $this->putJson($url, ['password' => $password, 'password_confirmation' => 'mismatch'])
                ->assertUnprocessable()->assertJsonValidationErrors('password');
        }
        $this->putJson($url, ['password' => '1234567', 'password_confirmation' => '1234567'])
            ->assertUnprocessable()->assertJsonValidationErrors('password');
        $this->putJson($url, ['password' => '12345678', 'password_confirmation' => '12345678'])->assertOk();
        $this->assertTrue(Hash::check('12345678', $target->fresh()->password));
        $this->assertSame(1, $target->fresh()->credential_version);
        $this->postJson('/api/admin/users', ['name' => 'Example Person', 'email' => 'person@example.test',
            'password' => '12345678', 'password_confirmation' => '12345678', 'enabled' => true, 'client_ids' => []])->assertCreated();
        $this->withoutVite()->get('/admin/users')->assertOk()->assertSee('data-password-min-length="8"', false);
    }

    public function test_short_existing_password_can_be_changed_with_eight_character_policy(): void
    {
        config(['auth-manager.password_min_length' => 8]);
        $user = User::factory()->create(['password' => 'oldpass', 'user_role' => 'user']);
        $this->actingAs($user)->withoutVite()->get('/settings')->assertOk()->assertSee('data-password-min-length="8"', false);
        $this->putJson('/settings/password', ['current_password' => 'oldpass', 'password' => '1234567', 'password_confirmation' => '1234567'])
            ->assertUnprocessable()->assertJsonValidationErrors('password');
        $this->putJson('/settings/password', ['current_password' => 'wrong', 'password' => '12345678', 'password_confirmation' => '12345678'])
            ->assertUnprocessable()->assertJsonValidationErrors('current_password');
        $this->putJson('/settings/password', ['current_password' => 'oldpass', 'password' => '12345678', 'password_confirmation' => '12345678'])->assertOk();
        $this->assertTrue(Hash::check('12345678', $user->fresh()->password));
        $this->assertSame(1, $user->fresh()->credential_version);
        $this->assertGuest();
    }

    public function test_lower_minimum_keeps_the_bcrypt_byte_limit(): void
    {
        config(['auth-manager.password_min_length' => 8]);
        $user = User::factory()->create(['password' => 'oldpass', 'user_role' => 'user']);
        $password = str_repeat('é', 40);
        $this->actingAs($user)->putJson('/settings/password', ['current_password' => 'oldpass',
            'password' => $password, 'password_confirmation' => $password])->assertUnprocessable()->assertJsonValidationErrors('password');
        $this->assertSame(0, $user->fresh()->credential_version);
        $this->assertTrue(Hash::check('oldpass', $user->fresh()->password));
    }

    public function test_environment_setting_is_bounded_and_invalid_values_fail_closed(): void
    {
        $previousEnv = $_ENV['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] ?? null;
        $previousServer = $_SERVER['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] ?? null;
        try {
            foreach (['8' => 8, '12' => 12, '72' => 72] as $value => $expected) {
                $_ENV['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = $_SERVER['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = (string) $value;
                $config = require config_path('auth-manager.php');
                $this->assertSame($expected, $config['password_min_length']);
            }
            foreach (['7', '73', 'invalid', '8.5', ''] as $value) {
                $_ENV['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = $_SERVER['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = $value;
                try {
                    require config_path('auth-manager.php');
                    $this->fail('Invalid password minimum was accepted.');
                } catch (\InvalidArgumentException $e) {
                    $this->assertStringContainsString('AUTH_MANAGER_PASSWORD_MIN_LENGTH', $e->getMessage());
                }
            }
        } finally {
            if ($previousEnv === null) {
                unset($_ENV['AUTH_MANAGER_PASSWORD_MIN_LENGTH']);
            } else {
                $_ENV['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = $previousEnv;
            }
            if ($previousServer === null) {
                unset($_SERVER['AUTH_MANAGER_PASSWORD_MIN_LENGTH']);
            } else {
                $_SERVER['AUTH_MANAGER_PASSWORD_MIN_LENGTH'] = $previousServer;
            }
        }
    }

    public function test_default_policy_stays_at_twelve_characters(): void
    {
        $this->assertSame(12, config('auth-manager.password_min_length'));
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create();
        $this->actingAs($admin)->putJson("/api/admin/users/{$target->id}/password", [
            'password' => '12345678', 'password_confirmation' => '12345678',
        ])->assertUnprocessable()->assertJsonValidationErrors('password');
    }
}
