<?php

namespace Tests\Feature;

use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ManageUserRolesTest extends TestCase
{
    use RefreshDatabase;

    public function test_grants_and_revokes_idempotently_and_audits_only_changes(): void
    {
        $user = User::factory()->create(['email' => 'operator@example.test', 'user_role' => 'user,admin']);

        $this->artisan('auth-manager:user-roles', ['user' => 'OPERATOR@example.test', '--add' => ['access-view:e-sign', 'Access-Manage:*']])
            ->expectsOutputToContain('Added access-view:e-sign, access-manage:*; removed none')->assertExitCode(0);
        $this->assertSame(['user', 'admin', 'access-view:e-sign', 'access-manage:*'], $user->fresh()->roleNames());

        $this->artisan('auth-manager:user-roles', ['user' => (string) $user->id, '--add' => ['access-view:e-sign']])
            ->expectsOutputToContain('Unchanged: user, admin, access-view:e-sign, access-manage:*')->assertExitCode(0);
        $this->artisan('auth-manager:user-roles', ['user' => (string) $user->id, '--remove' => ['access-manage:*', 'not-held']])
            ->expectsOutputToContain('Added none; removed access-manage:*')->assertExitCode(0);
        $this->artisan('auth-manager:user-roles', ['user' => (string) $user->id])
            ->expectsOutputToContain('Roles: user, admin, access-view:e-sign')->assertExitCode(0);

        $this->assertSame(2, AuthAuditLog::query()->where('event', 'user_roles_changed')->where('user_id', $user->id)->count());
        $this->assertSame(['added' => [], 'removed' => ['access-manage:*']], AuthAuditLog::query()->where('event', 'user_roles_changed')->latest('id')->first()->metadata);
    }

    public function test_refuses_malformed_roles_unknown_people_and_contradictions(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);

        foreach (['user,admin', 'access-edit:e-sign', 'access-view:', 'access-view:E Sign', ' '] as $role) {
            $this->artisan('auth-manager:user-roles', ['user' => (string) $user->id, '--add' => [$role]])->assertExitCode(2);
        }
        $this->artisan('auth-manager:user-roles', ['user' => (string) $user->id, '--add' => ['admin'], '--remove' => ['admin']])->assertExitCode(2);
        $this->artisan('auth-manager:user-roles', ['user' => 'nobody@example.test', '--add' => ['admin']])->assertExitCode(1);

        $this->assertSame(['user'], $user->fresh()->roleNames());
        $this->assertSame(0, AuthAuditLog::query()->where('event', 'user_roles_changed')->count());
    }
}
