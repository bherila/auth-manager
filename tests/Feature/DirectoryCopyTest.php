<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\AccessInvitation;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\DirectoryCopy\PrivateArchiveFile;
use BWH\AuthManager\Services\IdentityCopy\TableSequence;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class DirectoryCopyTest extends TestCase
{
    use RefreshDatabase;

    private string $path;

    protected function setUp(): void
    {
        parent::setUp();
        $this->path = sys_get_temp_dir().'/directory-copy-'.Str::uuid().'.json';
        config(['app.url' => 'https://id.example.test', 'bherila-auth.passkeys.rp_id' => 'example.test']);
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
        DB::setDefaultConnection('sqlite');
        DB::purge('directory-target');
        parent::tearDown();
    }

    public function test_directory_preserves_subjects_credentials_clients_roles_and_grants_and_replay_is_noop(): void
    {
        $person = User::factory()->create(['id' => 17, 'email' => 'person@example.test', 'user_role' => 'admin,user', 'password' => 'long-test-password']);
        $person->forceFill(['credential_version' => 7])->save();
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example app', ['https://app.example.test/oauth/callback']);
        $secret = $client->plainSecret;
        DB::table('oauth_clients')->where('id', $client->id)->update(['provider' => 'auth-manager-users']);
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $client->id, 'subject' => $person->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('users')->where('id', 17)->update(['remember_token' => 'not-portable']);
        $snapshot = app(DirectoryTransfer::class)->snapshot();
        $archive = DirectoryArchive::decode(DirectoryArchive::encode($snapshot));
        $this->target();

        $transfer = app(DirectoryTransfer::class);
        $plan = $transfer->import($archive['checksum'], $archive['payload'], false);
        $this->assertSame(1, $plan['users']);
        $this->assertSame(0, DB::table('users')->count());
        $transfer->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(17, User::firstOrFail()->id);
        $this->assertTrue(Hash::check('long-test-password', User::firstOrFail()->password));
        $this->assertSame('admin,user', User::firstOrFail()->user_role);
        $this->assertSame(7, User::firstOrFail()->credential_version);
        $this->assertNull(User::firstOrFail()->remember_token);
        $copied = DB::table('oauth_clients')->where('id', $client->id)->first();
        $this->assertSame('users', $copied->provider);
        $this->assertTrue(Hash::check($secret, $copied->secret));
        $this->assertSame(1, DB::table('oauth_client_grants')->count());
        DB::table('users')->where('id', 17)->update(['last_login_date' => now(), 'name' => 'Changed after cutover']);
        $again = $transfer->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(1, $again['already_imported']);
        $this->assertSame('Changed after cutover', User::firstOrFail()->name);
        $this->assertSame(1, DB::table('directory_imports')->count());
    }

    public function test_soft_deleted_and_tombstoned_subjects_cannot_be_reallocated(): void
    {
        User::factory()->create(['id' => 21, 'deleted_at' => now()]);
        DB::table('identity_tombstones')->insert(['id' => 5, 'public_id' => (string) Str::uuid(), 'subject' => 58, 'tombstoned_at' => now(), 'purge_after' => now()->addMonth(), 'created_at' => now(), 'updated_at' => now()]);
        $archive = $this->archive();
        $this->target();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertNotNull(User::withTrashed()->findOrFail(21)->deleted_at);
        $this->assertSame(58, (int) DB::table('identity_tombstones')->value('subject'));
        $this->assertGreaterThanOrEqual(59, (new TableSequence(DB::connection()))->next('users'));
        $this->assertGreaterThanOrEqual(59, User::factory()->create()->id);
    }

    public function test_compatible_passkey_binary_data_and_original_rp_id_are_preserved(): void
    {
        $this->passkey('example.test');
        $archive = $this->archive();
        $this->target();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $row = DB::table('webauthn_credentials')->first();
        $this->assertSame("binary\x00\xffcredential", $row->public_key);
        $this->assertSame('example.test', $row->rp_id);
        $this->assertSame(12, (int) $row->user_id);
        $this->assertSame('opaque-credential', $row->credential_id);
    }

    public function test_incompatible_rp_id_fails_closed_and_only_explicit_skip_omits_credentials(): void
    {
        $this->passkey('different.example.test');
        $archive = $this->archive();
        $this->target();
        try {
            app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
            $this->fail('An incompatible RP ID was accepted.');
        } catch (\InvalidArgumentException $failure) {
            $this->assertStringContainsString('1 passkeys', $failure->getMessage());
        }
        $this->assertSame(0, DB::table('users')->count());
        $plan = app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], false, true);
        $this->assertSame(1, $plan['passkeys_omitted']);
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true, true);
        $this->assertSame(1, DB::table('users')->count());
        $this->assertSame(0, DB::table('webauthn_credentials')->count());
    }

    public function test_invitation_business_state_and_operation_id_survive_but_live_credentials_do_not(): void
    {
        $person = User::factory()->create();
        DB::table('registered_applications')->insert(['id' => 1, 'key' => 'example-app', 'name' => 'Example', 'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $token = hash('sha256', 'one-time-link');
        DB::table('access_invitations')->insert([
            'id' => 4, 'application' => 'example-app', 'email' => 'invited@example.test', 'email_normalized' => 'invited@example.test', 'token_hash' => $token,
            'pending_key' => AccessInvitation::pendingKey('example-app', 'invited@example.test'), 'inviter_id' => $person->id, 'inviter_credential_version' => 0,
            'access' => json_encode(['application_admin' => false, 'workspaces' => []]), 'expires_at' => now()->addDay(), 'roles_operation_id' => 'operation-kept',
        ]);
        DB::table('sessions')->insert(['id' => 'old-session', 'user_id' => $person->id, 'payload' => 'old-payload', 'last_activity' => time()]);
        $archive = $this->archive();
        $this->assertArrayNotHasKey('sessions', $archive['payload']['tables']);
        $this->target();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame($token, DB::table('access_invitations')->value('token_hash'));
        $this->assertSame('operation-kept', DB::table('access_invitations')->value('roles_operation_id'));
        $this->assertSame(0, DB::table('sessions')->count());
        $this->assertSame(0, DB::table('invitation_acceptance_codes')->count());
        $this->assertSame(0, DB::table('oauth_access_tokens')->count());
    }

    public function test_nonempty_directory_is_never_adopted_by_matching_address(): void
    {
        User::factory()->create(['id' => 9, 'email' => 'same@example.test']);
        $archive = $this->archive();
        $this->target();
        User::factory()->create(['id' => 1, 'email' => 'same@example.test']);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('not fresh');
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
    }

    public function test_corrupt_archive_is_refused_and_file_permissions_and_no_overwrite_are_enforced(): void
    {
        $bytes = DirectoryArchive::encode(app(DirectoryTransfer::class)->snapshot());
        PrivateArchiveFile::write($this->path, $bytes);
        $this->assertSame(0600, fileperms($this->path) & 0777);
        $this->assertSame($bytes, PrivateArchiveFile::read($this->path));
        try {
            PrivateArchiveFile::write($this->path, 'overwrite');
            $this->fail('Existing file was overwritten.');
        } catch (\InvalidArgumentException) {
            $this->assertSame($bytes, file_get_contents($this->path));
        }
        $bad = json_decode($bytes, true);
        $bad['sha256'] = str_repeat('0', 64);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('checksum');
        DirectoryArchive::decode(json_encode($bad));
    }

    public function test_commands_require_private_files_and_dry_run_is_default(): void
    {
        User::factory()->create();
        $this->assertSame(0, Artisan::call('identity:directory-export', ['--output' => $this->path]));
        $this->assertStringNotContainsString('"payload"', Artisan::output());
        $this->target();
        $this->assertSame(0, Artisan::call('identity:directory-import', ['--input' => $this->path]));
        $this->assertStringContainsString('Dry run', Artisan::output());
        $this->assertSame(0, DB::table('users')->count());
        chmod($this->path, 0644);
        $this->assertSame(1, Artisan::call('identity:directory-import', ['--input' => $this->path, '--apply' => true]));
        $this->assertSame(0, DB::table('users')->count());
    }

    public function test_unknown_client_provider_is_refused_without_secret_disclosure(): void
    {
        app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example app', ['https://app.example.test/oauth/callback']);
        DB::table('oauth_clients')->update(['provider' => 'foreign-users']);
        $this->assertSame(1, Artisan::call('identity:directory-export', ['--output' => $this->path]));
        $this->assertStringContainsString('foreign user provider', Artisan::output());
        $this->assertFileDoesNotExist($this->path);
    }

    public function test_unknown_password_hash_requires_an_explicit_recovery_plan_and_is_reported(): void
    {
        User::factory()->create(['id' => 18]);
        DB::table('users')->where('id', 18)->update(['password' => 'unsupported-source-hash']);
        $archive = $this->archive();
        $this->assertNull(DirectoryArchive::unpackRow($archive['payload']['tables']['users'][0])['password']);
        $this->target();
        try {
            app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
            $this->fail('An unsupported password hash was accepted.');
        } catch (\InvalidArgumentException $failure) {
            $this->assertStringContainsString('1 password hashes', $failure->getMessage());
        }
        $plan = app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], false, false, true);
        $this->assertSame(1, $plan['passwords_requiring_reset']);
        $this->assertSame(0, DB::table('users')->count());
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true, false, true);
        $this->assertNotSame('unsupported-source-hash', User::findOrFail(18)->password);
        $this->assertSame('bcrypt', password_get_info(User::findOrFail(18)->password)['algoName']);
        $this->assertSame(1, User::findOrFail(18)->credential_version);
    }

    public function test_failed_apply_rolls_back_all_rows_and_same_archive_can_resume_after_correction(): void
    {
        User::factory()->create(['id' => 27]);
        app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example', ['https://app.example.test/oauth/callback']);
        $archive = $this->archive();
        $this->target();
        DB::statement("CREATE TRIGGER reject_client BEFORE INSERT ON oauth_clients BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
        try {
            app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
            $this->fail('The synthetic write failure was ignored.');
        } catch (QueryException) {
            $this->assertSame(0, DB::table('users')->count());
            $this->assertSame(0, DB::table('directory_imports')->count());
        }
        $this->assertGreaterThanOrEqual(28, (new TableSequence(DB::connection()))->next('users'));
        DB::statement('DROP TRIGGER reject_client');
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(27, User::firstOrFail()->id);
        $this->assertSame(1, DB::table('directory_imports')->count());
    }

    public function test_invalid_references_are_refused_during_dry_run(): void
    {
        $this->passkey('example.test');
        $snapshot = app(DirectoryTransfer::class)->snapshot();
        $snapshot['tables']['passkeys'][0]['user_id'] = base64_encode('999');
        $archive = DirectoryArchive::decode(DirectoryArchive::encode($snapshot));
        $this->target();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('missing referenced');
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], false);
    }

    public function test_export_refuses_application_and_web_root_paths(): void
    {
        $unsafe = public_path('directory-archive-'.Str::uuid().'.json');
        $this->assertSame(1, Artisan::call('identity:directory-export', ['--output' => $unsafe]));
        $this->assertStringContainsString('outside the application and web root', Artisan::output());
        $this->assertFileDoesNotExist($unsafe);
    }

    public function test_receipt_is_a_singleton_and_a_different_archive_cannot_be_imported_even_after_edits(): void
    {
        User::factory()->create(['id' => 15]);
        $archive = $this->archive();
        $this->target();
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(1, (int) DB::table('directory_imports')->value('id'));
        User::findOrFail(15)->update(['name' => 'Changed after cutover']);
        $payload = $archive['payload'];
        $payload['source_issuer'] = 'https://other.example.test';
        $different = DirectoryArchive::decode(DirectoryArchive::encode($payload));
        try {
            app(DirectoryTransfer::class)->import($different['checksum'], $different['payload'], true);
            $this->fail('A second archive was allowed.');
        } catch (\InvalidArgumentException) {
            $this->assertSame('Changed after cutover', User::findOrFail(15)->name);
        }
        $this->assertSame(1, DB::table('directory_imports')->count());
        $this->expectException(UniqueConstraintViolationException::class);
        DB::table('directory_imports')->insert(['id' => 1, 'checksum' => $different['checksum'], 'report' => '{}', 'created_at' => now()]);
    }

    public function test_copy_cannot_silently_weaken_password_second_factor_or_passkey_assurance(): void
    {
        $this->passkey('example.test');
        config(['auth-manager.sign_in.code_after_password' => true, 'auth-manager.sign_in.code_only' => false, 'bherila-auth.passkeys.user_verification' => 'required']);
        $archive = $this->archive();
        $this->target();
        $settings = [
            ['auth-manager.sign_in.code_after_password', false, true],
            ['auth-manager.sign_in.code_only', true, false],
            ['auth-manager.sign_in.trusted_devices', true, false],
            ['bherila-auth.passkeys.user_verification', 'preferred', 'required'],
        ];
        foreach ($settings as [$key, $weaker, $original]) {
            config([$key => $weaker]);
            try {
                app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], false);
                $this->fail('A weaker target assurance setting was accepted: '.$key);
            } catch (\InvalidArgumentException $failure) {
                $this->assertStringContainsString('weaker than the source', $failure->getMessage());
                $this->assertSame(0, DB::table('users')->count());
            }
            config([$key => $original]);
        }
        app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
        $this->assertSame(1, DB::table('webauthn_credentials')->count());
    }

    /** @return array{checksum: string, payload: array<string, mixed>} */
    private function archive(): array
    {
        return DirectoryArchive::decode(DirectoryArchive::encode(app(DirectoryTransfer::class)->snapshot()));
    }

    private function target(): void
    {
        config(['database.connections.directory-target' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]]);
        DB::setDefaultConnection('directory-target');
        config(['passport.connection' => 'directory-target']);
        $this->artisan('migrate', ['--database' => 'directory-target', '--force' => true])->assertSuccessful();
    }

    private function passkey(string $rp): void
    {
        User::factory()->create(['id' => 12]);
        DB::table('webauthn_credentials')->insert([
            'id' => 7, 'user_id' => 12, 'credential_id' => 'opaque-credential', 'credential_id_hash' => hash('sha256', 'opaque-credential'), 'public_key' => "binary\x00\xffcredential",
            'counter' => 8, 'name' => 'Key', 'rp_id' => $rp,
        ]);
    }
}
