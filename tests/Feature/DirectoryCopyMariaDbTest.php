<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\IdentityCopy\TableSequence;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/** Identifier-floor DDL and transaction rollback are validated only on CI's isolated engine. */
#[Group('mariadb')]
class DirectoryCopyMariaDbTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->artisan('migrate:fresh')->assertSuccessful();
    }

    public function test_portable_import_preserves_subjects_and_auto_increment_floor(): void
    {
        User::factory()->create(['id' => 17]);
        User::factory()->create(['id' => 400])->forceDelete();
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example', ['https://app.example.test/oauth/callback']);
        $archive = DirectoryArchive::decode(DirectoryArchive::encode(app(DirectoryTransfer::class)->snapshot()));
        $this->artisan('migrate:fresh')->assertSuccessful();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(17, User::firstOrFail()->id);
        $this->assertSame(1, DB::table('oauth_clients')->where('id', $client->id)->count());
        $this->assertSame(401, (new TableSequence(DB::connection()))->next('users'));
        $this->assertSame(401, User::factory()->create()->id);
        $this->assertSame(1, app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true)['already_imported']);
    }
}
