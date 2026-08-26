<?php

namespace Tests\Unit;

use App\Models\User;
use PHPUnit\Framework\TestCase;

class UserAccountStatusTest extends TestCase
{
    private function userWithRole(string $role): User
    {
        $user = new User;
        $user->setRawAttributes(['user_role' => $role]);

        return $user;
    }

    public function test_roles_are_matched_case_insensitively_and_ignore_surrounding_space(): void
    {
        $user = $this->userWithRole(' Admin , user ');

        $this->assertTrue($user->hasRole('admin'));
        $this->assertTrue($user->hasRole('USER'));
    }

    public function test_an_unlisted_role_is_not_granted(): void
    {
        $this->assertFalse($this->userWithRole('user')->hasRole('admin'));
    }

    public function test_a_partial_role_name_does_not_match(): void
    {
        $this->assertFalse($this->userWithRole('superuser')->hasRole('user'));
    }

    public function test_only_user_or_admin_may_authenticate(): void
    {
        $this->assertTrue($this->userWithRole('user')->canLogin());
        $this->assertTrue($this->userWithRole('admin')->canLogin());
        $this->assertFalse($this->userWithRole('pending')->canLogin());
        $this->assertFalse($this->userWithRole('')->canLogin());
    }

    public function test_an_explicitly_disabled_account_cannot_authenticate_without_losing_its_roles(): void
    {
        $user = $this->userWithRole('admin');
        $user->setRawAttributes([
            'user_role' => 'admin',
            'disabled_at' => now()->toDateTimeString(),
        ]);

        $this->assertTrue($user->hasRole('admin'));
        $this->assertFalse($user->canLogin());
    }
}
