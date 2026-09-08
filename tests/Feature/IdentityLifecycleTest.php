<?php

namespace Tests\Feature;

use App\Models\IdentityTombstone;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class IdentityLifecycleTest extends TestCase
{
    use RefreshDatabase;

    public function test_lifecycle_requires_an_active_provider_admin(): void
    {
        $this->get('/admin/identity-lifecycle')->assertRedirect('/login');
        $this->getJson('/api/admin/identity-lifecycle')->assertUnauthorized();

        foreach ([['user_role' => 'user'], ['user_role' => 'admin', 'disabled_at' => now()]] as $attributes) {
            $user = User::factory()->create($attributes);
            $this->actingAs($user)->get('/admin/identity-lifecycle')->assertForbidden();
            $this->actingAs($user)->getJson('/api/admin/identity-lifecycle')->assertForbidden();
        }
    }

    public function test_provider_purge_and_retention_do_not_acknowledge_applications_or_expose_user_profiles(): void
    {
        $this->withoutVite();
        $admin = User::factory()->create(['user_role' => 'admin']);
        $subject = User::factory()->create(['name' => 'Private Example Name', 'email' => 'private-profile@example.test']);
        $tombstone = $this->tombstone($subject->id);
        $tombstone->update(['provider_purged_at' => now(), 'purge_reason' => 'retention_expired']);
        $pending = $tombstone->clients()->create([
            'oauth_client_id' => (string) Str::uuid(),
            'oauth_client_name' => 'Example Pending Application',
        ]);
        $tombstone->clients()->create([
            'oauth_client_id' => (string) Str::uuid(),
            'oauth_client_name' => 'Example Finished Application',
            'acknowledged_at' => now(),
        ]);

        $response = $this->actingAs($admin)->getJson('/api/admin/identity-lifecycle')->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertJsonPath('data.0.pending_count', 1)
            ->assertJsonPath('data.0.retention_expired', true)
            ->assertJsonPath('data.0.applications.0.status', 'pending')
            ->assertJsonPath('data.0.applications.0.acknowledged_at', null)
            ->assertJsonPath('data.0.applications.1.status', 'acknowledged');
        $this->assertNotNull($response->json('data.0.provider_purged_at'));
        $this->assertStringNotContainsString($subject->name, $response->getContent());
        $this->assertStringNotContainsString($subject->email, $response->getContent());
        $this->assertSame([
            'id', 'subject', 'tombstoned_at', 'purge_after', 'provider_purged_at',
            'retention_expired', 'pending_count', 'applications',
        ], array_keys($response->json('data.0')));

        $this->actingAs($admin)->get('/admin/identity-lifecycle')->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('1 pending of 2 expected')
            ->assertSee('Purged at')
            ->assertSee('Pending acknowledgement')
            ->assertDontSee($subject->name)
            ->assertDontSee($subject->email);
        $this->assertNull($pending->fresh()->acknowledged_at);
        $this->assertSame(1, IdentityTombstone::count());
    }

    public function test_lifecycle_pagination_and_empty_snapshots_are_explicit(): void
    {
        $this->withoutVite();
        $admin = User::factory()->create(['user_role' => 'admin']);
        $this->actingAs($admin)->get('/admin/identity-lifecycle')->assertOk()
            ->assertSee('No identity deletions have been recorded.');
        for ($subject = 100; $subject < 126; $subject++) {
            $this->tombstone($subject);
        }
        $this->getJson('/api/admin/identity-lifecycle')->assertOk()
            ->assertJsonCount(25, 'data')->assertJsonPath('has_more', true)
            ->assertJsonPath('data.0.subject', '125');
        $this->getJson('/api/admin/identity-lifecycle?page=2')->assertOk()
            ->assertJsonCount(1, 'data')->assertJsonPath('has_more', false)
            ->assertJsonPath('data.0.subject', '100');
        $this->getJson('/api/admin/identity-lifecycle?page=0')->assertUnprocessable();
        $this->get('/admin/identity-lifecycle?page=2')->assertOk()
            ->assertSee('No applications were expected in the deletion snapshot.');
    }

    private function tombstone(int $subject): IdentityTombstone
    {
        return IdentityTombstone::create([
            'public_id' => (string) Str::uuid(),
            'subject' => $subject,
            'tombstoned_at' => now()->subDays(31),
            'purge_after' => now()->subDay(),
        ]);
    }
}
