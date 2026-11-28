<?php

namespace Tests\Feature;

use BWH\Auth\Models\PasskeyCredential;
use BWH\AuthManager\Http\Controllers\DirectoryAdminController;
use BWH\AuthManager\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

/**
 * Directory administration lists people a page at a time, so a directory of any size loads in
 * a bounded number of queries, and finds one person by name, email or subject.
 */
final class DirectoryAdminListingTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_listing_is_paginated_in_name_order(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin', 'name' => 'Aaron Synthetic']);
        foreach (range(1, 7) as $index) {
            User::factory()->create(['name' => sprintf('Person %02d', $index)]);
        }

        $first = $this->actingAs($admin)->getJson('/api/admin/users?per_page=3')->assertOk();
        $this->assertSame(['Aaron Synthetic', 'Person 01', 'Person 02'], array_column($first->json('users'), 'name'));
        $first->assertJsonPath('pagination', ['page' => 1, 'per_page' => 3, 'total' => 8, 'last_page' => 3]);

        $last = $this->getJson('/api/admin/users?per_page=3&page=3')->assertOk();
        $this->assertSame(['Person 06', 'Person 07'], array_column($last->json('users'), 'name'));

        $this->getJson('/api/admin/users')->assertJsonPath('pagination.per_page', DirectoryAdminController::PER_PAGE);
    }

    public function test_paging_and_filters_are_bounded(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);

        foreach (['per_page=101', 'per_page=0', 'page=0', 'status=owner', 'group=-1', 'search='.str_repeat('a', 256), 'subject='.str_repeat('a', 65)] as $bad) {
            $this->actingAs($admin)->getJson('/api/admin/users?'.$bad)->assertUnprocessable();
        }
    }

    public function test_search_matches_name_email_or_an_exact_subject_and_treats_wildcards_literally(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin', 'name' => 'Admin Synthetic', 'email' => 'admin@example.test']);
        $byName = User::factory()->create(['name' => 'Rowan Example', 'email' => 'one@example.test']);
        $byEmail = User::factory()->create(['name' => 'Someone', 'email' => 'rowan.mail@example.test']);
        $literal = User::factory()->create(['name' => '100% synthetic', 'email' => 'percent@example.test']);
        User::factory()->create(['name' => '1000 synthetic', 'email' => 'other@example.test']);

        $found = $this->actingAs($admin)->getJson('/api/admin/users?search=ROWAN')->assertOk();
        $this->assertEqualsCanonicalizing([$byName->id, $byEmail->id], array_column($found->json('users'), 'id'));

        $this->assertSame([$literal->id], array_column($this->getJson('/api/admin/users?search='.rawurlencode('0%'))->json('users'), 'id'));
        $this->assertSame([], $this->getJson('/api/admin/users?search=_')->json('users'));

        $subject = $byEmail->fresh()->providerSubject();
        $this->assertSame([$byEmail->id], array_column($this->getJson('/api/admin/users?search='.rawurlencode($subject))->json('users'), 'id'));
    }

    public function test_a_name_outside_ascii_is_found_by_the_text_it_is_stored_as(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $accented = User::factory()->create(['name' => 'Élodie Synthetic']);
        $cyrillic = User::factory()->create(['name' => 'Иван Synthetic']);

        $ids = fn (string $search): array => array_column($this->actingAs($admin)->getJson('/api/admin/users?search='.rawurlencode($search))->assertOk()->json('users'), 'id');

        $this->assertSame([$accented->id], $ids('Élodie'));
        $this->assertSame([$accented->id], $ids('ÉLODIE SYNTH'));
        $this->assertSame([$cyrillic->id], $ids('Иван'));
    }

    public function test_a_subject_opens_exactly_one_person(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create();
        User::factory()->count(3)->create();

        $response = $this->actingAs($admin)->getJson('/api/admin/users?subject='.rawurlencode($person->fresh()->providerSubject()))->assertOk();

        $this->assertSame([$person->id], array_column($response->json('users'), 'id'));
        $this->assertSame([], $this->getJson('/api/admin/users?subject=nobody')->json('users'));
    }

    public function test_status_and_group_filters_match_what_each_row_reports(): void
    {
        $admin = User::factory()->create(['user_role' => 'user, Admin']);
        $active = User::factory()->create(['user_role' => 'user']);
        $disabled = User::factory()->create(['user_role' => 'user', 'disabled_at' => now()]);
        $roleless = User::factory()->create(['user_role' => 'auditor']);
        $member = User::factory()->create(['user_role' => 'user']);
        $group = DB::table('access_groups')->insertGetId(['name' => 'Synthetic group', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('access_group_members')->insert(['access_group_id' => $group, 'subject' => $member->id, 'created_at' => now(), 'updated_at' => now()]);

        $ids = fn (string $query): array => array_column($this->actingAs($admin)->getJson('/api/admin/users?'.$query)->assertOk()->json('users'), 'id');

        $this->assertEqualsCanonicalizing([$admin->id, $active->id, $member->id], $ids('status=active'));
        $this->assertEqualsCanonicalizing([$disabled->id, $roleless->id], $ids('status=disabled'));
        $this->assertSame([$admin->id], $ids('status=administrators'));
        $this->assertSame([$member->id], $ids('group='.$group));

        $rows = collect($this->getJson('/api/admin/users')->json('users'))->keyBy('id');
        foreach ($ids('status=active') as $id) {
            $this->assertSame('active', $rows[$id]['status']);
        }
        foreach ($ids('status=disabled') as $id) {
            $this->assertSame('disabled', $rows[$id]['status']);
        }
    }

    public function test_a_page_loads_in_a_fixed_number_of_queries_however_many_people_it_shows(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/callback']);
        $count = function () use ($admin): int {
            DB::flushQueryLog();
            DB::enableQueryLog();
            $this->actingAs($admin)->getJson('/api/admin/users?per_page=100')->assertOk();
            $queries = count(DB::getQueryLog());
            DB::disableQueryLog();

            return $queries;
        };

        $this->person($client->getKey());
        $few = $count();
        foreach (range(1, 20) as $ignored) {
            $this->person($client->getKey());
        }

        $this->assertSame($few, $count());
    }

    public function test_each_row_carries_its_own_grants_groups_and_passkeys(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', ['https://app.example.test/callback']);
        $with = $this->person($client->getKey());
        $without = User::factory()->create();

        $rows = collect($this->actingAs($admin)->getJson('/api/admin/users')->json('users'))->keyBy('id');

        $this->assertSame([(string) $client->getKey()], $rows[$with->id]['client_ids']);
        $this->assertSame([(string) $client->getKey()], $rows[$with->id]['direct_client_ids']);
        $this->assertCount(1, $rows[$with->id]['group_ids']);
        $this->assertSame(1, $rows[$with->id]['passkey_count']);
        $this->assertSame([], $rows[$without->id]['client_ids']);
        $this->assertSame([], $rows[$without->id]['group_ids']);
        $this->assertSame(0, $rows[$without->id]['passkey_count']);
    }

    public function test_one_person_can_be_read_by_id(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create(['name' => 'Synthetic Reader']);

        $this->actingAs($admin)->getJson("/api/admin/users/{$person->id}")
            ->assertOk()
            ->assertJsonPath('user.name', 'Synthetic Reader')
            ->assertJsonPath('user.subject', $person->fresh()->providerSubject());
        $this->getJson('/api/admin/users/999999')->assertNotFound();
        $this->actingAs(User::factory()->create())->getJson("/api/admin/users/{$person->id}")->assertForbidden();
    }

    public function test_groups_report_their_member_count(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $member = User::factory()->create();
        $group = DB::table('access_groups')->insertGetId(['name' => 'Counted group', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('access_group_members')->insert(['access_group_id' => $group, 'subject' => $member->id, 'created_at' => now(), 'updated_at' => now()]);

        $this->actingAs($admin)->getJson('/api/admin/groups')->assertOk()->assertJsonPath('groups.0.member_count', 1);
    }

    private function person(string $clientId): User
    {
        $user = User::factory()->create();
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $clientId, 'subject' => $user->id, 'direct' => true, 'created_at' => now(), 'updated_at' => now()]);
        $group = DB::table('access_groups')->insertGetId(['name' => 'Group '.$user->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('access_group_members')->insert(['access_group_id' => $group, 'subject' => $user->id, 'created_at' => now(), 'updated_at' => now()]);
        PasskeyCredential::query()->create(['user_id' => $user->id, 'credential_id' => 'synthetic-'.$user->id, 'public_key' => 'synthetic', 'counter' => 0]);

        return $user;
    }
}
