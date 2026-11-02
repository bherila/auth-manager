<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Models\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/**
 * What SQLite can't stand in for: MariaDB can give a table's first TIMESTAMP column
 * ON UPDATE CURRENT_TIMESTAMP, and restricts deleting from a table a subquery also reads.
 * Runs only in the MariaDB lane (phpunit.mariadb.xml), against a throwaway server.
 */
#[Group('mariadb')]
class TrustedDevicesMariaDbTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->artisan('migrate:fresh')->assertSuccessful();
        config(['auth-manager.sign_in.code_after_password' => true, 'auth-manager.sign_in.trusted_devices' => true]);
    }

    public function test_recording_a_use_leaves_the_expiry_alone(): void
    {
        $user = User::factory()->create();
        $expires = now()->addDays(30)->startOfSecond();
        $device = $this->device($user, 'used', (int) $user->credential_version, $expires);

        $device->forceFill(['last_used_at' => now()])->save();

        $this->assertSame($expires->getTimestamp(), $device->fresh()->expires_at->getTimestamp());
    }

    public function test_pruning_removes_expired_and_outdated_rows_and_keeps_the_rest(): void
    {
        $user = User::factory()->create();
        $current = (int) $user->credential_version;
        $kept = $this->device($user, 'kept', $current, now()->addDay());
        $this->device($user, 'expired', $current, now()->subSecond());
        $this->device($user, 'outdated', $current + 1, now()->addDay());

        $this->assertSame(2, TrustedDevice::pruneUnusable());
        $this->assertSame([$kept->getKey()], TrustedDevice::query()->pluck('id')->all());
    }

    private function device(User $user, string $name, int $version, Carbon $expires): TrustedDevice
    {
        return TrustedDevice::query()->create([
            'user_id' => $user->getKey(),
            'token_hash' => hash('sha256', $name),
            'credential_version' => $version,
            'expires_at' => $expires,
        ]);
    }
}
