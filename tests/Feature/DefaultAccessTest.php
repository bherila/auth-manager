<?php

namespace Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Models\AccessGroup;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AccessGroupService;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

/**
 * Default access (docs/default-access.md): groups new accounts join automatically, opt-outs an
 * administrator records by taking someone out, and a previewed backfill for existing accounts.
 */
final class DefaultAccessTest extends TestCase
{
    use RefreshDatabase;

    private User $admin;

    private string $defaultClient;

    private string $otherClient;

    protected function setUp(): void
    {
        parent::setUp();
        $this->admin = User::factory()->create(['user_role' => 'admin']);
        $clients = app(ClientRepository::class);
        $this->defaultClient = (string) $clients->createAuthorizationCodeGrantClient('Default Application', ['https://default.example.test/callback'])->getKey();
        $this->otherClient = (string) $clients->createAuthorizationCodeGrantClient('Other Application', ['https://other.example.test/callback'])->getKey();
    }

    public function test_only_a_provider_administrator_makes_a_group_default_and_existing_people_are_not_added(): void
    {
        $existing = User::factory()->create();
        $group = $this->group('Everyone', false, $this->defaultClient);

        $this->actingAs(User::factory()->create())->putJson("/api/admin/groups/{$group->id}/auto-join", ['auto_join' => true])->assertForbidden();
        $this->actingAs($this->admin)->putJson("/api/admin/groups/{$group->id}/auto-join", [])->assertUnprocessable();

        $this->actingAs($this->admin)->putJson("/api/admin/groups/{$group->id}/auto-join", ['auto_join' => true])
            ->assertOk()
            ->assertJsonPath('group.auto_join', true)
            ->assertJsonPath('group.member_count', 0);

        $this->assertFalse($this->grants()->allows((string) $existing->id, $this->defaultClient));
        $audit = AuthAuditLog::query()->where('event', AccessGroupService::EVENT_AUTO_JOIN_CHANGED)->sole();
        $this->assertTrue($audit->metadata['auto_join']);
        $this->getJson('/api/admin/groups')->assertJsonPath('groups.0.auto_join', true);

        $this->putJson("/api/admin/groups/{$group->id}/auto-join", ['auto_join' => true])->assertOk();
        $this->assertSame(1, AuthAuditLog::query()->where('event', AccessGroupService::EVENT_AUTO_JOIN_CHANGED)->count());
    }

    public function test_an_account_an_administrator_creates_joins_every_default_group_and_no_other(): void
    {
        $default = $this->group('Everyone', true, $this->defaultClient);
        $ordinary = $this->group('Specialists', false, $this->otherClient);

        $response = $this->actingAs($this->admin)->postJson('/api/admin/users', [
            'name' => 'Synthetic Newcomer', 'email' => 'newcomer@example.test',
            'password' => 'synthetic-password-1', 'password_confirmation' => 'synthetic-password-1',
            'enabled' => false, 'client_ids' => [],
        ])->assertCreated();
        $person = User::query()->findOrFail($response->json('user.id'));

        $this->assertTrue($this->member($default, $person));
        $this->assertFalse($this->member($ordinary, $person));
        $this->assertTrue($this->grants()->allows((string) $person->id, $this->defaultClient));
        $this->assertFalse($this->grants()->allows((string) $person->id, $this->otherClient));
        $this->assertFalse((bool) DB::table('oauth_client_grants')->where('subject', $person->id)->value('direct'));
        $audit = AuthAuditLog::query()->where('event', AccessGroupService::EVENT_MEMBER_ADDED)->where('user_id', $person->id)->sole();
        $this->assertSame(AccessGroupService::JOINED_BY_DIRECTORY_ADMIN, $audit->metadata['joined_by']);
        $this->assertSame([$this->defaultClient], $audit->metadata['granted_oauth_client_ids']);
    }

    public function test_a_test_login_never_joins_a_default_group(): void
    {
        $default = $this->group('Everyone', true, $this->defaultClient);
        $synthetic = User::factory()->create();
        $synthetic->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()])->save();

        $this->assertSame([], app(AccessGroupService::class)->joinDefaultGroups($synthetic->fresh(), AccessGroupService::JOINED_BY_DIRECTORY_ADMIN));
        $this->assertFalse($this->member($default, $synthetic));
    }

    public function test_taking_someone_out_of_a_default_group_is_remembered_until_they_are_added_back(): void
    {
        $default = $this->group('Everyone', true, $this->defaultClient);
        $person = User::factory()->create();
        app(AccessGroupService::class)->joinDefaultGroups($person, AccessGroupService::JOINED_BY_DIRECTORY_ADMIN);

        $this->actingAs($this->admin)->deleteJson("/api/admin/groups/{$default->id}/members/{$person->id}")->assertOk();

        $this->assertFalse($this->member($default, $person));
        $this->assertFalse($this->grants()->allows((string) $person->id, $this->defaultClient));
        $this->assertTrue($this->optedOut($default, $person));
        $this->assertTrue(AuthAuditLog::query()->where('event', AccessGroupService::EVENT_MEMBER_REMOVED)->sole()->metadata['opted_out_of_default']);
        $row = collect($this->getJson('/api/admin/users')->json('users'))->firstWhere('id', $person->id);
        $this->assertSame([$default->id], $row['opted_out_group_ids']);

        $this->assertSame([], app(AccessGroupService::class)->joinDefaultGroups($person, AccessGroupService::JOINED_BY_DIRECTORY_ADMIN));
        $this->assertFalse($this->member($default, $person));

        $this->putJson("/api/admin/groups/{$default->id}/members/{$person->id}")->assertOk();
        $this->assertTrue($this->member($default, $person));
        $this->assertFalse($this->optedOut($default, $person));
    }

    public function test_leaving_an_ordinary_group_records_no_opt_out(): void
    {
        $ordinary = $this->group('Specialists', false, $this->otherClient);
        $person = User::factory()->create();
        $this->actingAs($this->admin)->putJson("/api/admin/groups/{$ordinary->id}/members/{$person->id}")->assertOk();
        $this->deleteJson("/api/admin/groups/{$ordinary->id}/members/{$person->id}")->assertOk();

        $this->assertFalse($this->optedOut($ordinary, $person));
    }

    public function test_the_backfill_previews_then_adds_only_eligible_people_and_is_idempotent(): void
    {
        $default = $this->group('Everyone', true, $this->defaultClient);
        $eligible = User::factory()->create(['name' => 'Eligible Synthetic']);
        $holdsDirectly = User::factory()->create(['name' => 'Direct Synthetic']);
        app(OAuthClientGrantService::class)->grant((string) $holdsDirectly->id, $this->defaultClient);
        $member = User::factory()->create();
        DB::table('access_group_members')->insert(['access_group_id' => $default->id, 'subject' => $member->id, 'created_at' => now(), 'updated_at' => now()]);
        $optedOut = User::factory()->create();
        DB::table('access_group_opt_outs')->insert(['access_group_id' => $default->id, 'subject' => $optedOut->id, 'created_at' => now(), 'updated_at' => now()]);
        $testLogin = User::factory()->create();
        $testLogin->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()])->save();
        $deleted = User::factory()->create();
        $deleted->delete();

        // The administrator from setUp is eligible too: three people would join, two would gain the application.
        $this->artisan('auth-manager:access-group-backfill', ['group' => 'Everyone'])
            ->expectsOutputToContain('Everyone: 3 people would join.')
            ->expectsOutputToContain('2 would gain it')
            ->expectsOutputToContain('Nothing was changed.')
            ->assertSuccessful();
        $this->assertFalse($this->member($default, $eligible));
        $this->assertSame(0, AuthAuditLog::query()->where('event', AccessGroupService::EVENT_MEMBER_ADDED)->count());

        $this->artisan('auth-manager:access-group-backfill', ['group' => (string) $default->id, '--apply' => true])
            ->expectsOutputToContain('Everyone: 3 people joined.')
            ->assertSuccessful();

        foreach ([$eligible, $holdsDirectly, $this->admin] as $joined) {
            $this->assertTrue($this->member($default, $joined));
            $this->assertTrue($this->grants()->allows((string) $joined->id, $this->defaultClient));
        }
        $this->assertTrue((bool) DB::table('oauth_client_grants')->where('subject', $holdsDirectly->id)->value('direct'));
        foreach ([$optedOut, $testLogin] as $skipped) {
            $this->assertFalse($this->member($default, $skipped));
        }
        $this->assertFalse(DB::table('access_group_members')->where('subject', $deleted->id)->exists());
        $this->assertSame(3, AuthAuditLog::query()->where('event', AccessGroupService::EVENT_MEMBER_ADDED)->count());

        $this->artisan('auth-manager:access-group-backfill', ['group' => 'Everyone', '--apply' => true])
            ->expectsOutputToContain('Everyone: 0 people joined.')
            ->assertSuccessful();
    }

    public function test_only_a_default_group_can_be_backfilled(): void
    {
        $this->group('Specialists', false, $this->otherClient);
        User::factory()->create();

        $this->artisan('auth-manager:access-group-backfill', ['group' => 'Specialists', '--apply' => true])
            ->expectsOutputToContain('Only a group that new accounts join automatically can be backfilled.')
            ->assertFailed();
        $this->artisan('auth-manager:access-group-backfill', ['group' => 'Nobody'])->assertFailed();
        $this->assertSame(0, DB::table('access_group_members')->count());
    }

    private function group(string $name, bool $autoJoin, string $clientId): AccessGroup
    {
        $group = AccessGroup::query()->create(['name' => $name, 'auto_join' => $autoJoin]);
        DB::table('access_group_clients')->insert(['access_group_id' => $group->id, 'oauth_client_id' => $clientId, 'created_at' => now(), 'updated_at' => now()]);

        return $group;
    }

    private function member(AccessGroup $group, User $person): bool
    {
        return DB::table('access_group_members')->where('access_group_id', $group->id)->where('subject', $person->id)->exists();
    }

    private function optedOut(AccessGroup $group, User $person): bool
    {
        return DB::table('access_group_opt_outs')->where('access_group_id', $group->id)->where('subject', $person->id)->exists();
    }

    private function grants(): OAuthClientGrantService
    {
        return app(OAuthClientGrantService::class);
    }
}
