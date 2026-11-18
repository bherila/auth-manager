<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AccessGroupService;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

/** Groups grant sign-in to their applications, expanded into ordinary per-person grants. */
class AccessGroupTest extends TestCase
{
    use RefreshDatabase;

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->admin = User::factory()->create(['user_role' => 'admin']);
    }

    protected function tearDown(): void
    {
        DB::setDefaultConnection('sqlite');
        DB::purge('group-copy-target');
        parent::tearDown();
    }

    public function test_only_an_active_provider_administrator_manages_groups(): void
    {
        $this->getJson('/api/admin/groups')->assertUnauthorized();
        $person = User::factory()->create(['user_role' => 'user']);
        $this->actingAs($person)->getJson('/api/admin/groups')->assertForbidden();
        $this->actingAs($person)->postJson('/api/admin/groups', ['name' => 'Staff', 'description' => null])->assertForbidden();
        $this->assertSame(0, DB::table('access_groups')->count());
    }

    public function test_joining_a_group_grants_its_applications_and_leaving_revokes_them_with_their_tokens(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        $group = $this->group('Staff');
        $this->asAdmin()->putJson("/api/admin/groups/{$group}/clients/{$clientId}")->assertOk()->assertJsonPath('group.client_ids', [$clientId]);

        $this->asAdmin()->putJson("/api/admin/groups/{$group}/members/{$person->id}")->assertOk()->assertJsonPath('group.member_ids', [$person->id]);

        $this->assertTrue($this->allows($person, $clientId));
        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $person->id, 'oauth_client_id' => $clientId, 'direct' => false]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $person->id, 'acting_user_id' => $this->admin->id, 'event' => AccessGroupService::EVENT_MEMBER_ADDED]);
        $token = $this->accessToken($person, $clientId);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$group}/members/{$person->id}")->assertOk()->assertJsonPath('group.member_ids', []);

        $this->assertFalse($this->allows($person, $clientId));
        $this->assertDatabaseMissing('oauth_client_grants', ['subject' => $person->id, 'oauth_client_id' => $clientId]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token, 'revoked' => true]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $person->id, 'event' => AccessGroupService::EVENT_MEMBER_REMOVED]);
    }

    public function test_a_direct_grant_survives_leaving_a_group_that_also_grants_the_application(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $person->id, $clientId);
        $group = $this->group('Staff', clients: [$clientId], members: [$person]);
        $token = $this->accessToken($person, $clientId);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$group}/members/{$person->id}")->assertOk();

        $this->assertTrue($this->allows($person, $clientId));
        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $person->id, 'oauth_client_id' => $clientId, 'direct' => true]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token, 'revoked' => false]);
    }

    public function test_removing_a_direct_grant_keeps_access_a_group_still_gives(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $person->id, $clientId);
        $group = $this->group('Staff', clients: [$clientId], members: [$person]);
        $token = $this->accessToken($person, $clientId);

        $this->asAdmin()->deleteJson("/api/admin/users/{$person->id}/clients/{$clientId}")
            ->assertOk()
            ->assertJsonPath('user.client_ids', [$clientId])
            ->assertJsonPath('user.direct_client_ids', [])
            ->assertJsonPath('user.group_ids', [$group]);

        $this->assertTrue($this->allows($person, $clientId), 'The group still grants the application.');
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token, 'revoked' => false]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $person->id, 'event' => DirectoryAdminService::EVENT_CLIENT_REVOKED]);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$group}/members/{$person->id}")->assertOk();

        $this->assertFalse($this->allows($person, $clientId));
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token, 'revoked' => true]);
    }

    public function test_a_group_only_grant_cannot_be_revoked_as_a_direct_grant(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        $this->group('Staff', clients: [$clientId], members: [$person]);

        $this->assertFalse(app(OAuthClientGrantService::class)->revoke((string) $person->id, $clientId));
        $this->assertTrue($this->allows($person, $clientId));
    }

    public function test_a_direct_grant_on_group_access_is_recorded_as_direct(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        $this->group('Staff', clients: [$clientId], members: [$person]);

        $this->asAdmin()->putJson("/api/admin/users/{$person->id}/clients/{$clientId}")
            ->assertOk()
            ->assertJsonPath('user.direct_client_ids', [$clientId]);

        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $person->id, 'oauth_client_id' => $clientId, 'direct' => true]);
        $this->assertSame(1, DB::table('oauth_client_grants')->where('subject', $person->id)->count());
    }

    public function test_leaving_one_of_two_groups_for_the_same_application_keeps_access(): void
    {
        $clientId = $this->client();
        $person = User::factory()->create(['user_role' => 'user']);
        $staff = $this->group('Staff', clients: [$clientId], members: [$person]);
        $this->group('Clients', clients: [$clientId], members: [$person]);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$staff}/members/{$person->id}")->assertOk();

        $this->assertTrue($this->allows($person, $clientId));
    }

    public function test_adding_and_removing_an_application_changes_every_member(): void
    {
        $clientId = $this->client();
        $first = User::factory()->create(['user_role' => 'user']);
        $second = User::factory()->create(['user_role' => 'user']);
        $direct = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $direct->id, $clientId);
        $group = $this->group('Staff', members: [$first, $second, $direct]);

        $this->asAdmin()->putJson("/api/admin/groups/{$group}/clients/{$clientId}")->assertOk();

        $this->assertTrue($this->allows($first, $clientId));
        $this->assertTrue($this->allows($second, $clientId));
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $first->id, 'event' => DirectoryAdminService::EVENT_CLIENT_GRANTED]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => null, 'event' => AccessGroupService::EVENT_CLIENT_ADDED]);
        $this->assertDatabaseMissing('auth_audit_log', ['user_id' => $direct->id, 'event' => DirectoryAdminService::EVENT_CLIENT_GRANTED]);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$group}/clients/{$clientId}")->assertOk()->assertJsonPath('group.client_ids', []);

        $this->assertFalse($this->allows($first, $clientId));
        $this->assertFalse($this->allows($second, $clientId));
        $this->assertTrue($this->allows($direct, $clientId), 'A direct grant is independent of the group.');
    }

    public function test_deleting_a_group_revokes_what_only_it_granted(): void
    {
        $clientId = $this->client();
        $member = User::factory()->create(['user_role' => 'user']);
        $direct = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $direct->id, $clientId);
        $group = $this->group('Staff', clients: [$clientId], members: [$member, $direct]);
        $token = $this->accessToken($member, $clientId);

        $this->asAdmin()->deleteJson("/api/admin/groups/{$group}")->assertNoContent();

        $this->assertSame(0, DB::table('access_groups')->count());
        $this->assertSame(0, DB::table('access_group_members')->count());
        $this->assertFalse($this->allows($member, $clientId));
        $this->assertTrue($this->allows($direct, $clientId));
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $token, 'revoked' => true]);
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => null, 'event' => AccessGroupService::EVENT_GROUP_DELETED]);
    }

    public function test_test_logins_revoked_applications_and_duplicate_names_are_refused(): void
    {
        $group = $this->group('Staff');
        $synthetic = User::factory()->make(['email' => 'synthetic@example.test', 'user_role' => 'user']);
        $synthetic->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()])->save();
        $revoked = $this->client('Retired Application', revoked: true);

        $this->asAdmin()->putJson("/api/admin/groups/{$group}/members/{$synthetic->id}")->assertUnprocessable()->assertJsonValidationErrors('user');
        $this->asAdmin()->putJson("/api/admin/groups/{$group}/clients/{$revoked}")->assertUnprocessable()->assertJsonValidationErrors('client');
        $this->asAdmin()->postJson('/api/admin/groups', ['name' => 'Staff', 'description' => null])->assertUnprocessable()->assertJsonValidationErrors('name');
        $this->assertSame(0, DB::table('access_group_members')->count());
        $this->assertSame(0, DB::table('access_group_clients')->count());
    }

    public function test_a_group_can_be_renamed_and_described(): void
    {
        $group = $this->group('Staff');

        $this->asAdmin()->patchJson("/api/admin/groups/{$group}", ['name' => 'Office staff', 'description' => '  Everyone in the office  '])
            ->assertOk()
            ->assertJsonPath('group.name', 'Office staff')
            ->assertJsonPath('group.description', 'Everyone in the office');
        $this->assertDatabaseHas('auth_audit_log', ['event' => AccessGroupService::EVENT_GROUP_UPDATED]);
    }

    public function test_a_directory_copy_carries_groups_and_which_grants_are_direct(): void
    {
        config(['app.url' => 'https://id.example.test', 'bherila-auth.passkeys.rp_id' => 'example.test']);
        $clientId = $this->client();
        $member = User::factory()->create(['user_role' => 'user']);
        $direct = User::factory()->create(['user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $direct->id, $clientId);
        $group = $this->group('Staff', clients: [$clientId], members: [$member]);
        $archive = DirectoryArchive::decode(DirectoryArchive::encode(app(DirectoryTransfer::class)->snapshot()));

        config(['database.connections.group-copy-target' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]]);
        DB::setDefaultConnection('group-copy-target');
        config(['passport.connection' => 'group-copy-target']);
        $this->artisan('migrate', ['--database' => 'group-copy-target', '--force' => true])->assertSuccessful();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);

        $this->assertDatabaseHas('access_groups', ['id' => $group, 'name' => 'Staff'], 'group-copy-target');
        $this->assertDatabaseHas('access_group_members', ['access_group_id' => $group, 'subject' => $member->id], 'group-copy-target');
        $this->assertDatabaseHas('access_group_clients', ['access_group_id' => $group, 'oauth_client_id' => $clientId], 'group-copy-target');
        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $member->id, 'oauth_client_id' => $clientId, 'direct' => false], 'group-copy-target');
        $this->assertDatabaseHas('oauth_client_grants', ['subject' => $direct->id, 'oauth_client_id' => $clientId, 'direct' => true], 'group-copy-target');
    }

    private function asAdmin(): self
    {
        return $this->actingAs($this->admin);
    }

    /**
     * @param  list<string>  $clients
     * @param  list<User>  $members
     */
    private function group(string $name, array $clients = [], array $members = []): int
    {
        $id = (int) $this->asAdmin()->postJson('/api/admin/groups', ['name' => $name, 'description' => null])
            ->assertCreated()
            ->json('group.id');
        foreach ($clients as $clientId) {
            $this->asAdmin()->putJson("/api/admin/groups/{$id}/clients/{$clientId}")->assertOk();
        }
        foreach ($members as $member) {
            $this->asAdmin()->putJson("/api/admin/groups/{$id}/members/{$member->id}")->assertOk();
        }

        return $id;
    }

    private function allows(User $user, string $clientId): bool
    {
        return app(OAuthClientGrantService::class)->allows((string) $user->id, $clientId);
    }

    private function client(string $name = 'Example Application', bool $revoked = false): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => $name,
            'secret' => null,
            'redirect_uris' => json_encode(['https://app.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code', 'refresh_token']),
            'revoked' => $revoked,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    private function accessToken(User $user, string $clientId): string
    {
        $id = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $clientId,
            'name' => null,
            'scopes' => '[]',
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }
}
