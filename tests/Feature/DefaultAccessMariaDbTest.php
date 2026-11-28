<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\AccessGroup;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AccessGroupService;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/**
 * Under repeatable read, a transaction that took its snapshot (for example an email check before
 * creating an account) and only then locks a default group must still grant the group's
 * applications as they are now, not as its snapshot saw them. Real second connection; runs only
 * against the isolated MariaDB CI service.
 */
#[Group('mariadb')]
class DefaultAccessMariaDbTest extends TestCase
{
    public function test_joining_after_an_older_snapshot_grants_the_groups_current_applications(): void
    {
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->artisan('migrate:fresh')->assertSuccessful();
        $clients = app(ClientRepository::class);
        $removed = (string) $clients->createAuthorizationCodeGrantClient('Removed Application', ['https://removed.example.test/callback'])->getKey();
        $added = (string) $clients->createAuthorizationCodeGrantClient('Added Application', ['https://added.example.test/callback'])->getKey();
        $group = AccessGroup::query()->create(['name' => 'Everyone', 'auto_join' => true]);
        DB::table('access_group_clients')->insert(['access_group_id' => $group->id, 'oauth_client_id' => $removed, 'created_at' => now(), 'updated_at' => now()]);

        $default = config('database.default');
        config(['database.connections.default_access_other' => config("database.connections.{$default}")]);
        $other = DB::connection('default_access_other');

        DB::beginTransaction();
        try {
            // The creating transaction's first consistent read fixes its snapshot.
            $this->assertSame(1, DB::table('access_group_clients')->where('access_group_id', $group->id)->count());

            // Another administrator changes the group's applications and commits.
            $other->table('access_group_clients')->where('access_group_id', $group->id)->delete();
            $other->table('access_group_clients')->insert(['access_group_id' => $group->id, 'oauth_client_id' => $added, 'created_at' => now(), 'updated_at' => now()]);

            $person = User::factory()->create();
            app(AccessGroupService::class)->joinDefaultGroups($person, AccessGroupService::JOINED_BY_APPLICATION_REGISTRATION);
            DB::commit();
        } catch (\Throwable $failure) {
            DB::rollBack();
            throw $failure;
        } finally {
            $other->disconnect();
        }

        $grants = app(OAuthClientGrantService::class);
        $this->assertTrue($grants->allows((string) $person->id, $added));
        $this->assertFalse($grants->allows((string) $person->id, $removed));
    }
}
