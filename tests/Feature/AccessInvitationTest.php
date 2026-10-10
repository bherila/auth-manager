<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Mail\AccessInvitationMail;
use App\Models\AccessInvitation;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Services\DirectoryAdminService;
use App\Services\IdentityTombstonePurger;
use App\Services\Invitations\AccessInvitationService;
use App\Services\Invitations\InvitationAudit;
use App\Services\Invitations\InvitationRoles;
use App\Services\Invitations\InvitationUnavailable;
use App\Support\DelegatedAccessPermissions;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * Invitations by email to a contract version 2 (and, where noted, 3) application: who may send them, what the inviter
 * learns, the link's life, and applying the invited access at acceptance as the inviter.
 */
class AccessInvitationTest extends TestCase
{
    use DatabaseMigrations;

    public function runDatabaseMigrations(): void
    {
        // Real transport writes require independently committed audit records.
        $this->refreshTestDatabase();
        $this->beforeApplicationDestroyed(function (): void {
            RefreshDatabaseState::$migrated = false;
        });
    }

    private string $keyPath;

    private string $otherKeyPath;

    private User $inviter;

    /** @var array<string, PassportClient> */
    private array $clients = [];

    /** Accounts the fake application holds, by subject. */
    private array $accounts = [];

    private bool $provisioning = true;

    /** Actor-scoped `controls.application_admin`: false for a workspace-scoped administrator. */
    private bool $applicationAdmin = true;

    /** Role ids the fake application advertises; null for all four. */
    private ?array $advertisedRoles = null;

    private bool $refuseUpdates = false;

    private bool $failUpdates = false;

    /** The contract version the fake applications speak: 3 adds operation ids, receipts and `allowed_edits.remove`. */
    private int $contractVersion = 2;

    /** Version 3: apply the write, then answer it with a 503 as though the answer were lost. */
    private bool $loseUpdateAnswers = false;

    /** Version 3: stored outcomes by operation id, as the package endpoint keeps them. */
    private array $receipts = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-invitations-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        $this->otherKeyPath = tempnam(sys_get_temp_dir(), 'synthetic-invitations-other-');
        file_put_contents($this->otherKeyPath, $private);
        chmod($this->otherKeyPath, 0600);
        config(['application-registry.launch_enabled' => true, 'delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'writes_applications' => ['example-app', 'other-app'],
            'issuer' => 'https://identity.example.test', 'key_id' => null, 'private_key_path' => null,
            'keys_environment' => 'example-app|example-v1|'.$this->keyPath.',other-app|other-v1|'.$this->otherKeyPath,
            'applications' => [
                'example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 2],
                'other-app' => ['endpoint' => 'https://other.example.test/access', 'contract_version' => 2],
            ],
            'invitations' => ['enabled' => true, 'expires_after_days' => 7, 'per_inviter_per_hour' => 20, 'per_recipient_per_day' => 5],
        ]]);
        foreach (['example-app' => 'Example Application', 'other-app' => 'Other Application'] as $keyName => $name) {
            $this->clients[$keyName] = PassportClient::create(['id' => (string) Str::uuid(), 'name' => "{$name} Client",
                'secret' => 'example-secret', 'grant_types' => ['authorization_code'],
                'redirect_uris' => ["https://{$keyName}.example.test/callback"], 'revoked' => false]);
            RegisteredApplication::create(['key' => $keyName, 'name' => $name, 'launch_url' => "https://{$keyName}.example.test", 'enabled' => true])
                ->clients()->attach($this->clients[$keyName]->id);
        }
        $this->inviter = User::factory()->create(['name' => 'Example Inviter', 'email' => 'inviter@example.test',
            'user_role' => 'user,access-manage:example-app,access-invite:example-app', 'password' => Hash::make('current-password-example')]);
        $this->grant($this->inviter, 'example-app');
        Http::preventStrayRequests();
        $this->fakeApplications();
        // A delivering mailer name: invitations refuse `log` and `array`. Mail::fake() intercepts sending.
        config(['mail.default' => 'smtp']);
        Mail::fake();
        $this->signIn($this->inviter);
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        @unlink($this->otherKeyPath);
        parent::tearDown();
    }

    public function test_inviting_needs_the_invite_permission_as_well_as_manage(): void
    {
        foreach (['user,access-manage:example-app', 'user,access-invite:example-app', 'user,access-view:example-app,access-invite:example-app'] as $roles) {
            $this->inviter->forceFill(['user_role' => $roles])->save();
            $this->confirmIfPossible();
            $this->invite('person@example.test')->assertRedirect('/applications/example-app/access')->assertSessionHas('access_failure');
        }

        $this->assertSame(0, AccessInvitation::query()->count());
        Mail::assertNothingSent();
    }

    public function test_an_invite_permission_for_one_application_does_not_reach_another(): void
    {
        $this->inviter->forceFill(['user_role' => 'user,access-manage:*,access-invite:example-app'])->save();
        $this->grant($this->inviter, 'other-app');
        $this->confirm('example-app');
        $this->invite('person@example.test')->assertSessionHas('invitation_notice');

        $this->confirm('other-app');
        $this->invite('someone@example.test', 'other-app')->assertSessionHas('access_failure');
        $this->assertSame(['example-app'], AccessInvitation::query()->pluck('application')->all());

        // The other application's page lists none of this application's invitations and offers no form.
        $this->get('/applications/other-app/access')->assertOk()
            ->assertSee('No invitations to this application yet.')
            ->assertDontSee('person@example.test')
            ->assertDontSee('Send invitation');
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->post("/applications/other-app/access/invitations/{$invitation->id}/revoke")->assertNotFound();
        $this->post("/applications/other-app/access/invitations/{$invitation->id}/resend")->assertNotFound();
        $this->assertTrue(AccessInvitation::query()->firstOrFail()->isPending());
    }

    public function test_inviting_needs_a_recent_confirmation_and_writes_enabled(): void
    {
        $this->invite('person@example.test')->assertSessionHas('access_failure', fn (string $message): bool => str_contains($message, 'Confirm your password'));

        $this->confirm();
        config(['delegated-access.writes_applications' => ['other-app']]);
        $this->invite('person@example.test')->assertSessionHas('access_failure');

        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_switched_off_invitations_show_nothing_and_accept_nothing(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        config(['delegated-access.invitations.enabled' => false]);

        $this->get('/applications/example-app/access')->assertOk()->assertDontSee('Invitations');
        $this->invite('other@example.test')->assertNotFound();
        $this->get($link)->assertNotFound();
        $this->assertSame(1, AccessInvitation::query()->count());
    }

    public function test_the_inviter_gets_the_same_answer_whether_or_not_the_address_has_an_account(): void
    {
        User::factory()->create(['email' => 'existing@example.test', 'user_role' => 'user']);
        $this->confirm();

        $queries = [];
        DB::listen(function ($query) use (&$queries): void {
            $queries[] = $query->sql;
        });
        $existing = $this->invite('Existing@Example.test');
        $new = $this->invite('new-person@example.test');

        foreach ([$existing, $new] as $response) {
            $response->assertRedirect('/applications/example-app/access')
                ->assertSessionHas('invitation_notice', 'Invitation sent.')
                ->assertSessionHas('invitation_mail_failed', false)
                ->assertSessionMissing('invitation_link');
        }
        // Creating an invitation never looks the address up.
        $this->assertSame([], array_values(array_filter($queries, fn (string $sql): bool => str_contains($sql, '"users"') && str_contains($sql, 'email'))));

        $mails = Mail::sent(AccessInvitationMail::class);
        $this->assertCount(2, $mails);
        [$first, $second] = $mails->all();
        $this->assertSame($first->envelope()->subject, $second->envelope()->subject);
        $this->assertSame(
            str_replace($first->link, 'LINK', $first->render()),
            str_replace($second->link, 'LINK', $second->render()),
        );
        $this->assertTrue($first->hasTo('Existing@Example.test'));
    }

    public function test_the_access_is_chosen_explicitly_from_what_the_application_advertises(): void
    {
        $this->confirm();
        $this->invite('person@example.test', access: ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-a', 'role' => 'emperor']]])->assertSessionHasErrors('workspaces');
        $this->invite('person@example.test', access: ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-a', 'role' => '']]])->assertSessionHasErrors('workspaces');
        $this->invite('person@example.test', access: ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender'], ['id' => 'workspace-a', 'role' => 'auditor']]])->assertSessionHasErrors('workspaces');
        $this->invite('person@example.test', access: ['application_admin' => '0', 'workspaces' => []])->assertSessionHasErrors('workspaces');
        // The administrator choice is required when the application offers it, never defaulted.
        $this->invite('person@example.test', access: ['workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]])->assertSessionHasErrors('application_admin');

        $this->assertSame(0, AccessInvitation::query()->count());

        $this->invite('person@example.test', access: ['application_admin' => '1', 'workspaces' => []])->assertSessionHas('invitation_notice');
        $this->assertSame(['application_admin' => true, 'workspaces' => []], AccessInvitation::query()->firstOrFail()->access);
    }

    public function test_an_application_without_provisioning_cannot_be_offered(): void
    {
        $this->provisioning = false;
        $this->confirm();

        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('does not accept new accounts from this provider')
            ->assertDontSee('Send invitation');
        $this->invite('person@example.test')->assertSessionHasErrors('invitation');
        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_the_token_is_long_random_stored_only_as_a_hash_and_expires_after_seven_days(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $token = basename($link);

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $token);
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(hash('sha256', $token), $invitation->token_hash);
        $this->assertSame(0, DB::table('access_invitations')->where('token_hash', $token)->count());
        $this->assertSame(7, (int) round(now()->diffInDays($invitation->expires_at)));

        $this->signOutLocally();
        $this->get($link)->assertOk()->assertSee('Create account and accept');
        $this->travel(7)->days();
        $this->travel(1)->minutes();
        $this->get($link)->assertNotFound()->assertSee('This invitation link doesn');
        $this->post($link.'/accept', ['name' => 'Example Person', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])->assertNotFound();
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
    }

    public function test_a_revoked_invitation_stops_working_and_revoking_needs_the_invite_permission(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $invitation = AccessInvitation::query()->firstOrFail();

        $this->inviter->forceFill(['user_role' => 'user,access-manage:example-app'])->save();
        $this->post("/applications/example-app/access/invitations/{$invitation->id}/revoke")->assertSessionHas('access_failure');
        $this->assertTrue($invitation->fresh()->isPending());

        $this->inviter->forceFill(['user_role' => 'user,access-manage:example-app,access-invite:example-app'])->save();
        $this->post("/applications/example-app/access/invitations/{$invitation->id}/revoke")->assertSessionHas('invitation_notice');
        $this->assertSame(AccessInvitation::STATUS_REVOKED, $invitation->fresh()->status());
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::REVOKED, 'acting_user_id' => $this->inviter->id]);

        $this->signOutLocally();
        $this->get($link)->assertNotFound();
    }

    public function test_resending_issues_a_new_link_and_the_old_one_stops_working(): void
    {
        $this->confirm();
        $old = $this->inviteAndGetLink('person@example.test');
        $invitation = AccessInvitation::query()->firstOrFail();

        $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")->assertSessionHas('invitation_notice', 'Invitation sent.')
            ->assertSessionMissing('invitation_link');
        $new = $this->lastMailedLink();

        $this->assertNotSame($old, $new);
        Mail::assertSent(AccessInvitationMail::class, 2);
        $this->assertSame(2, $invitation->fresh()->send_count);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::RESENT]);
        $this->signOutLocally();
        $this->get($old)->assertNotFound();
        $this->get($new)->assertOk();
    }

    public function test_a_newer_invitation_for_the_same_address_and_application_supersedes_the_older_one(): void
    {
        User::factory()->create(['email' => 'existing@example.test', 'user_role' => 'user']);
        $this->inviter->forceFill(['user_role' => 'user,access-manage:*,access-invite:*'])->save();
        $this->grant($this->inviter, 'other-app');
        $this->confirm();
        $oldExisting = $this->inviteAndGetLink('existing@example.test');
        $oldNew = $this->inviteAndGetLink('new-person@example.test');
        $otherAddress = $this->inviteAndGetLink('unrelated@example.test');
        $this->confirm('other-app');
        $this->invite('existing@example.test', 'other-app');
        $otherApp = $this->lastMailedLink();

        // The same answer for both addresses, account or not, while the older links are revoked.
        $this->confirm();
        $responses = [];
        $links = [];
        foreach (['EXISTING@example.test', 'New-Person@example.test'] as $email) {
            $responses[] = $this->invite($email);
            $links[] = $this->lastMailedLink();
        }
        foreach ($responses as $response) {
            $response->assertRedirect('/applications/example-app/access')
                ->assertSessionHas('invitation_notice', 'Invitation sent.')
                ->assertSessionHas('invitation_mail_failed', false)
                ->assertSessionMissing('errors');
        }
        $superseded = AuthAuditLog::query()->where('event', InvitationAudit::REVOKED)->get();
        $this->assertCount(2, $superseded);
        $this->assertSame(['superseded', 'superseded'], $superseded->map(fn ($row) => $row->metadata['reason'])->all());
        $this->assertSame(array_keys($superseded[0]->metadata), array_keys($superseded[1]->metadata));

        [$newExisting, $newNew] = $links;
        // Resending the newest one supersedes nothing further, and keeps only its own new link working.
        $newest = AccessInvitation::query()->where('email_normalized', 'existing@example.test')->where('application', 'example-app')->latest('id')->firstOrFail();
        $this->post("/applications/example-app/access/invitations/{$newest->id}/resend");
        $resent = $this->lastMailedLink();

        $this->signOutLocally();
        $this->get($oldExisting)->assertNotFound();
        $this->get($oldNew)->assertNotFound();
        $this->get($newExisting)->assertNotFound();
        $this->get($resent)->assertOk();
        $this->get($newNew)->assertOk();
        $this->get($otherAddress)->assertOk();
        $this->get($otherApp)->assertOk();
        $this->assertSame(4, AccessInvitation::query()->whereNull('revoked_at')->count());
    }

    /**
     * A create that loses the pending key to a concurrent one runs once more and supersedes it (#76
     * review). Simulated: a competing pending row takes the key just before this create's insert.
     */
    public function test_the_database_allows_one_pending_invitation_per_application_and_address(): void
    {
        $this->confirm();
        $competed = false;
        AccessInvitation::creating(function (AccessInvitation $invitation) use (&$competed): void {
            if ($competed) {
                return;
            }
            $competed = true;
            AccessInvitation::withoutEvents(fn () => AccessInvitation::query()->create([
                ...$invitation->getAttributes(), 'token_hash' => hash('sha256', 'competitor'), 'access' => ['application_admin' => true, 'workspaces' => []],
            ]));
        });

        $this->invite('person@example.test')->assertSessionHas('invitation_notice', 'Invitation sent.');

        $this->assertTrue($competed);
        $pending = AccessInvitation::query()->get()->filter(fn (AccessInvitation $invitation): bool => $invitation->isPending());
        $this->assertCount(1, $pending);
        $this->assertSame(['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]], $pending->first()->access);
    }

    public function test_a_second_pending_row_for_the_same_pair_cannot_be_stored(): void
    {
        $this->confirm();
        $this->invite('person@example.test')->assertSessionHas('invitation_notice');
        $row = (array) DB::table('access_invitations')->first();
        unset($row['id']);

        $this->expectException(UniqueConstraintViolationException::class);
        DB::table('access_invitations')->insert([...$row, 'token_hash' => hash('sha256', 'concurrent'), 'email' => 'PERSON@example.test']);
    }

    public function test_resending_is_refused_when_the_application_no_longer_offers_provisioning_or_the_role(): void
    {
        $this->confirm();
        $this->invite('person@example.test')->assertSessionHas('invitation_notice');
        $invitation = AccessInvitation::query()->firstOrFail();
        $hash = $invitation->token_hash;

        $this->provisioning = false;
        $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")
            ->assertSessionHasErrors(['invitation' => 'The application no longer accepts new accounts from this provider, so this invitation cannot be sent again. Revoke it instead.']);
        $this->provisioning = true;
        $this->advertisedRoles = ['owner', 'auditor'];
        $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")
            ->assertSessionHasErrors(['invitation' => 'The application no longer offers the access this invitation gives, so it cannot be sent again. Revoke it and send a new one.']);

        $this->assertSame($hash, $invitation->fresh()->token_hash);
        Mail::assertSent(AccessInvitationMail::class, 1);
        $this->assertDatabaseMissing('auth_audit_log', ['event' => InvitationAudit::RESENT]);
    }

    public function test_a_new_person_creates_an_account_is_admitted_and_provisioned_as_the_inviter(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('New.Person@example.test', ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-b', 'role' => 'sender']]]);
        $this->signOutLocally();

        $this->get($link)->assertOk()->assertSee('Create account and accept')->assertSee('New.Person@example.test');
        $this->post($link.'/accept', ['name' => 'Example Person', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])
            ->assertRedirect('/invitations/accepted');

        $person = User::query()->where('email', 'New.Person@example.test')->firstOrFail();
        $this->assertNotNull($person->email_verified_at);
        $this->assertTrue($person->canLogin());
        $this->assertAuthenticatedAs($person);
        $this->assertTrue(DB::table('oauth_client_grants')->where('subject', $person->id)->where('oauth_client_id', $this->clients['example-app']->id)->exists());
        $this->assertFalse(DB::table('oauth_client_grants')->where('subject', $person->id)->where('oauth_client_id', $this->clients['other-app']->id)->exists());

        $updates = $this->updates();
        $this->assertCount(1, $updates);
        $this->assertNull($updates[0]['expected_revision']);
        $this->assertSame((string) $person->id, $updates[0]['subject']);
        $this->assertSame(['application_admin' => false, 'workspaces' => [['id' => 'workspace-b', 'role' => 'sender']]], $updates[0]['access']);
        $this->assertSame('Example Person', $updates[0]['display_name']);
        $this->assertSame((string) $this->inviter->id, $this->claims($updates[0])['sub']);

        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::STATUS_ACCEPTED, $invitation->status());
        $this->assertSame($person->id, $invitation->accepted_user_id);
        $this->assertSame(AccessInvitation::ROLES_APPLIED, $invitation->roles_status);
        $this->assertSame($this->claims($updates[0])['jti'], $invitation->roles_request_id);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::ACCEPTED, 'user_id' => $person->id]);
        $applied = AuthAuditLog::query()->where('event', InvitationAudit::ROLES_APPLIED)->firstOrFail();
        $this->assertSame($invitation->roles_request_id, $applied->metadata['correlation']);
        $this->assertSame($this->inviter->id, $applied->acting_user_id);
        $this->assertSame('invitation', AuthAuditLog::query()->where('event', 'delegated_access_update_result')->firstOrFail()->metadata['via']);
        $this->get('/invitations/accepted')->assertOk()->assertSee('You can now sign in to Example Application');

        // Used once.
        $this->post('/logout');
        $this->get($link)->assertNotFound();
    }

    public function test_an_existing_account_signs_in_as_itself_and_gains_only_the_missing_memberships(): void
    {
        $person = User::factory()->create(['email' => 'existing@example.test', 'user_role' => 'user']);
        $this->accounts[(string) $person->id] = ['application_admin' => false, 'revision' => 'revision-1', 'workspaces' => [
            ['id' => 'workspace-a', 'role' => 'owner', 'editable' => false],
        ]];
        $this->confirm();
        $link = $this->inviteAndGetLink('EXISTING@example.test', ['application_admin' => '0', 'workspaces' => [
            ['id' => 'workspace-a', 'role' => 'sender'], ['id' => 'workspace-b', 'role' => 'auditor'],
        ]]);

        $this->signOutLocally();
        $this->get($link)->assertOk()->assertSee('Sign in as EXISTING@example.test');
        $this->get($link.'/sign-in')->assertRedirect('/login')->assertSessionHas('url.intended', url($link));
        $this->post($link.'/accept', ['name' => 'Someone', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])
            ->assertRedirect($link);
        $this->assertSame(1, User::query()->where('email', 'like', '%existing%')->count());

        $this->signIn($person);
        $this->get($link)->assertOk()->assertSee('Accept invitation');
        $this->post($link.'/accept')->assertRedirect('/invitations/accepted');

        $updates = $this->updates();
        $this->assertCount(1, $updates);
        $this->assertSame('revision-1', $updates[0]['expected_revision']);
        $this->assertSame(['application_admin' => false, 'workspaces' => [
            ['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor'],
        ]], $updates[0]['access']);
        $this->assertArrayNotHasKey('display_name', $updates[0]);
        $this->assertSame(AccessInvitation::ROLES_APPLIED, AccessInvitation::query()->firstOrFail()->roles_status);
        $this->assertTrue(DB::table('oauth_client_grants')->where('subject', $person->id)->where('oauth_client_id', $this->clients['example-app']->id)->exists());
    }

    public function test_an_existing_administrator_is_never_demoted_and_nothing_is_written_when_nothing_is_missing(): void
    {
        $admin = User::factory()->create(['email' => 'admin@example.test', 'user_role' => 'user']);
        $member = User::factory()->create(['email' => 'member@example.test', 'user_role' => 'user']);
        $this->accounts[(string) $admin->id] = ['application_admin' => true, 'revision' => 'revision-admin', 'workspaces' => []];
        $this->accounts[(string) $member->id] = ['application_admin' => false, 'revision' => 'revision-member', 'workspaces' => [
            ['id' => 'workspace-a', 'role' => 'owner', 'editable' => true],
        ]];
        $this->confirm();
        $adminLink = $this->inviteAndGetLink('admin@example.test', ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-b', 'role' => 'sender']]]);
        $memberLink = $this->inviteAndGetLink('member@example.test', ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]]);

        $this->signIn($admin);
        $this->post($adminLink.'/accept')->assertRedirect('/invitations/accepted');
        $this->signIn($member);
        $this->post($memberLink.'/accept')->assertRedirect('/invitations/accepted');

        $updates = $this->updates();
        $this->assertCount(1, $updates, 'A membership already present, in any role, is left as it is and nothing is sent.');
        $this->assertSame(['application_admin' => true, 'workspaces' => [['id' => 'workspace-b', 'role' => 'sender']]], $updates[0]['access']);
        $this->assertSame(['applied', 'applied'], AccessInvitation::query()->orderBy('id')->pluck('roles_status')->all());
        $this->assertSame('nothing_to_add', AccessInvitation::query()->orderByDesc('id')->value('roles_outcome'));
        $this->assertSame('owner', $this->accounts[(string) $member->id]['workspaces'][0]['role']);
    }

    public function test_purging_the_recipients_identity_removes_their_invitations(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $person = $this->acceptAsNewPerson($link);
        $this->inviteAndGetLinkAs($this->inviter, 'PERSON@example.test');
        $this->inviteAndGetLinkAs($this->inviter, 'someone-else@example.test');

        $tombstone = app(DirectoryAdminService::class)->tombstone(request(), $this->inviter, $person);
        $tombstone->forceFill(['purge_after' => now()->subMinute()])->save();
        app(IdentityTombstonePurger::class)->purgeEligible();

        $this->assertSame(['someone-else@example.test'], AccessInvitation::query()->pluck('email')->all());
    }

    public function test_someone_signed_in_as_another_account_is_refused_and_offered_a_sign_out(): void
    {
        User::factory()->create(['email' => 'existing@example.test', 'user_role' => 'user']);
        $this->confirm();
        $existing = $this->inviteAndGetLink('existing@example.test');
        $new = $this->inviteAndGetLink('new-person@example.test');

        // Still signed in as the inviter: neither invitation is theirs.
        foreach ([$existing, $new] as $link) {
            $this->get($link)->assertOk()->assertSee('signed in as a different account')->assertSee('Sign out and continue');
            $this->post($link.'/accept', ['name' => 'Example Person', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])
                ->assertRedirect($link);
        }
        $this->assertSame(0, AccessInvitation::query()->whereNotNull('accepted_at')->count());
        $this->assertSame(0, User::query()->where('email', 'new-person@example.test')->count());
        $this->assertSame([], $this->updates());

        $this->post($existing.'/sign-out')->assertRedirect($existing);
        $this->assertGuest();
    }

    public function test_an_address_matching_several_accounts_case_insensitively_cannot_accept(): void
    {
        $lower = User::factory()->create(['email' => 'person@example.test', 'user_role' => 'user']);
        $upper = User::factory()->create(['email' => 'PERSON@example.test', 'user_role' => 'user']);
        $this->confirm();
        $this->invite('Person@example.test')->assertSessionHas('invitation_notice');
        $link = $this->lastMailedLink();

        foreach ([null, $lower, $upper] as $who) {
            $who === null ? $this->signOutLocally() : $this->signIn($who);
            $this->get($link)->assertOk()->assertSee('more than one account matches its address');
            $this->post($link.'/accept', ['name' => 'Someone', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])
                ->assertRedirect($link);
        }

        $this->assertTrue(AccessInvitation::query()->firstOrFail()->isPending());
        $this->assertSame(2, User::query()->whereRaw('lower(email) = ?', ['person@example.test'])->count());
        $this->assertFalse(DB::table('oauth_client_grants')->whereIn('subject', [$lower->id, $upper->id])->exists());
        $this->assertSame([], $this->updates());

        // The service refuses on its own too, whoever is named as signed in.
        $this->expectException(InvitationUnavailable::class);
        app(AccessInvitationService::class)->accept(request(), $invitation = AccessInvitation::query()->firstOrFail(), $invitation->token_hash, $lower, null);
    }

    public function test_a_link_replaced_by_a_resend_after_it_was_opened_cannot_accept(): void
    {
        $this->confirm();
        $this->invite('person@example.test')->assertSessionHas('invitation_notice');
        $old = basename($this->lastMailedLink());
        $service = app(AccessInvitationService::class);
        $opened = $service->findPending($old);
        $this->assertNotNull($opened);

        // A resend commits between opening the old link and accepting it.
        $this->post("/applications/example-app/access/invitations/{$opened->id}/resend")->assertSessionHas('invitation_notice');

        try {
            $service->accept(request(), $opened, AccessInvitation::hashToken($old), null, ['name' => 'Example Person', 'password' => 'a-new-password-example']);
            $this->fail('The replaced link must not accept.');
        } catch (InvitationUnavailable $refusal) {
            $this->assertSame('not_pending', $refusal->reason);
        }
        $this->assertTrue($opened->fresh()->isPending());
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
    }

    public function test_a_disabled_account_cannot_accept(): void
    {
        $person = User::factory()->create(['email' => 'disabled@example.test', 'user_role' => 'user', 'disabled_at' => now()]);
        $this->confirm();
        $link = $this->inviteAndGetLink('disabled@example.test');
        $this->signOutLocally();

        $this->get($link)->assertOk()->assertSee('can\'t sign in, so it can\'t accept', false);
        $this->post($link.'/accept', ['name' => 'Someone', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])->assertRedirect($link);

        $this->assertTrue(AccessInvitation::query()->firstOrFail()->isPending());
        $this->assertFalse(DB::table('oauth_client_grants')->where('subject', $person->id)->exists());
    }

    public function test_roles_are_not_applied_when_the_inviter_lost_permission_but_the_person_is_admitted(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $this->inviter->forceFill(['user_role' => 'user,access-manage:example-app'])->save();
        $before = count(Http::recorded());

        $person = $this->acceptAsNewPerson($link);

        $this->assertCount($before, Http::recorded(), 'Nothing is sent once the inviter is refused here.');
        $this->assertTrue(DB::table('oauth_client_grants')->where('subject', $person->id)->where('oauth_client_id', $this->clients['example-app']->id)->exists());
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_NOT_APPLIED, $invitation->roles_status);
        $this->assertSame('inviter_not_authorized', $invitation->roles_outcome);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::ROLES_NOT_APPLIED, 'user_id' => $person->id, 'succeeded' => false]);
        $this->get('/invitations/accepted')->assertSee('could not be set up yet');

        // A manager sees the flag.
        $this->signIn($this->inviter);
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('Accepted; roles not applied')
            ->assertSee('the inviter can no longer give this access');
    }

    public function test_roles_are_not_applied_when_the_inviter_is_disabled_or_writes_are_off(): void
    {
        $this->confirm();
        $first = $this->inviteAndGetLink('first@example.test');
        $second = $this->inviteAndGetLink('second@example.test');

        config(['delegated-access.writes_applications' => ['other-app']]);
        $this->acceptAsNewPerson($first);
        config(['delegated-access.writes_applications' => ['example-app', 'other-app']]);
        $this->inviter->forceFill(['disabled_at' => now()])->save();
        $this->acceptAsNewPerson($second);

        $this->assertSame(['inviter_not_authorized', 'inviter_not_authorized'],
            AccessInvitation::query()->orderBy('id')->pluck('roles_outcome')->all());
        $this->assertSame([], $this->updates());
    }

    public function test_a_credential_reset_of_the_inviter_voids_the_roles_but_the_person_is_admitted(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $this->assertSame(0, AccessInvitation::query()->firstOrFail()->inviter_credential_version);
        $this->inviter->forceFill(['credential_version' => 1])->save();
        $before = count(Http::recorded());

        $person = $this->acceptAsNewPerson($link);

        $this->assertCount($before, Http::recorded(), 'No application call is made for an inviter whose credentials changed.');
        $this->assertTrue(DB::table('oauth_client_grants')->where('subject', $person->id)->where('oauth_client_id', $this->clients['example-app']->id)->exists());
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_NOT_APPLIED, $invitation->roles_status);
        $this->assertSame('inviter_not_authorized', $invitation->roles_outcome);

        // The transport refuses the stale generation on its own too, before sending anything.
        try {
            app(DelegatedAccessTransport::class)->sendForInvitation($this->inviter->fresh(), 0, 'example-app', ['operation' => 'capabilities']);
            $this->fail('A stale credential generation must be refused.');
        } catch (DelegatedAccessException $refusal) {
            $this->assertSame('not_authorized', $refusal->outcome);
        }
        $this->assertCount($before, Http::recorded());
    }

    public function test_resending_records_the_resenders_credential_generation_and_makes_them_the_inviter(): void
    {
        $this->confirm();
        $this->inviteAndGetLink('person@example.test');
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->inviter->forceFill(['credential_version' => 3])->save();
        $this->signIn($this->inviter->fresh());
        $this->confirm();

        $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")->assertSessionHas('invitation_notice');
        $link = parse_url(Mail::sent(AccessInvitationMail::class)->last()->link, PHP_URL_PATH);

        $this->assertSame(3, $invitation->fresh()->inviter_credential_version);
        $this->acceptAsNewPerson($link);
        $this->assertSame(AccessInvitation::ROLES_APPLIED, AccessInvitation::query()->firstOrFail()->roles_status);
    }

    public function test_roles_are_not_applied_when_the_application_refuses(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $this->refuseUpdates = true;

        $person = $this->acceptAsNewPerson($link);

        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_NOT_APPLIED, $invitation->roles_status);
        $this->assertSame('not_authorized', $invitation->roles_outcome);
        $this->assertSame($this->claims($this->updates()[0])['jti'], $invitation->roles_request_id);
        $this->assertTrue(DB::table('oauth_client_grants')->where('subject', $person->id)->exists());
    }

    public function test_an_uncertain_write_is_recorded_as_unknown_and_never_retried(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $this->failUpdates = true;

        $this->acceptAsNewPerson($link);

        $this->assertCount(1, $this->updates());
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_UNKNOWN, $invitation->roles_status);
        $this->assertSame('unknown_outcome', $invitation->roles_outcome);

        $this->signIn($this->inviter);
        $this->get('/applications/example-app/access')->assertSee('Accepted; roles not confirmed');
        $this->assertCount(1, $this->updates());
    }

    public function test_on_a_version_3_application_the_acceptance_write_carries_the_invitations_operation_id(): void
    {
        $this->useVersion3();
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');

        $person = $this->acceptAsNewPerson($link);

        $updates = $this->updates();
        $this->assertCount(1, $updates);
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_APPLIED, $invitation->roles_status);
        $this->assertTrue(DelegatedContract::validOperationId($invitation->roles_operation_id));
        $this->assertSame(3, $updates[0]['contract_version']);
        $this->assertSame($invitation->roles_operation_id, $updates[0]['operation_id']);
        // Distinct from the assertion's single-use nonce.
        $this->assertNotSame($this->claims($updates[0])['jti'], $updates[0]['operation_id']);
        $this->assertSame((string) $person->id, $updates[0]['subject']);
        $this->assertSame($invitation->roles_operation_id, AuthAuditLog::query()->where('event', InvitationAudit::ROLES_APPLIED)->firstOrFail()->metadata['operation_id']);
        $this->assertSame($invitation->roles_operation_id, AuthAuditLog::query()->where('event', 'delegated_access_update_attempt')->firstOrFail()->metadata['operation_id']);
    }

    public function test_applying_an_invitation_again_reuses_its_stored_operation_id(): void
    {
        $this->useVersion3();
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');
        $this->failUpdates = true;
        $person = $this->acceptAsNewPerson($link);
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(AccessInvitation::ROLES_UNKNOWN, $invitation->roles_status);
        $stored = $invitation->roles_operation_id;
        $this->assertTrue(DelegatedContract::validOperationId($stored));

        // A later attempt for the same invitation is the same operation, never a new one.
        $this->failUpdates = false;
        $this->assertSame(AccessInvitation::ROLES_APPLIED, app(InvitationRoles::class)->apply($invitation->fresh(), $person));

        $this->assertSame([$stored, $stored], array_column($this->updates(), 'operation_id'));
        $this->assertSame($stored, $invitation->fresh()->roles_operation_id);
    }

    public function test_a_version_2_acceptance_write_carries_no_operation_id(): void
    {
        $this->confirm();
        $link = $this->inviteAndGetLink('person@example.test');

        $this->acceptAsNewPerson($link);

        $this->assertArrayNotHasKey('operation_id', $this->updates()[0]);
        $this->assertNull(AccessInvitation::query()->firstOrFail()->roles_operation_id);
    }

    public function test_the_invitation_path_refuses_without_the_invite_permission_whatever_the_session(): void
    {
        $this->confirm();
        $this->inviter->forceFill(['user_role' => 'user,access-manage:example-app'])->save();
        $before = count(Http::recorded());

        try {
            app(DelegatedAccessTransport::class)->sendForInvitation($this->inviter, (int) $this->inviter->credential_version, 'example-app', ['operation' => 'capabilities']);
            $this->fail('The invitation path must refuse an inviter without access-invite.');
        } catch (DelegatedAccessException $refusal) {
            $this->assertSame('not_authorized', $refusal->outcome);
        }
        $this->assertCount($before, Http::recorded());
    }

    public function test_invitations_are_rate_limited_per_recipient_and_per_inviter(): void
    {
        $this->confirm();
        for ($i = 0; $i < 5; $i++) {
            $this->invite('Person@example.test')->assertSessionHas('invitation_notice');
        }
        $this->invite('person@EXAMPLE.test')->assertSessionHasErrors('email');

        config(['delegated-access.invitations.per_inviter_per_hour' => 6]);
        $this->invite('another@example.test')->assertSessionHas('invitation_notice');
        $this->invite('yet-another@example.test')->assertSessionHasErrors('email');
        $this->assertSame(6, AccessInvitation::query()->count());
    }

    public function test_the_list_shows_this_applications_invitations_to_its_viewers_and_managers(): void
    {
        $this->confirm();
        $this->inviteAndGetLink('pending@example.test');
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('pending@example.test')->assertSee('Pending until')
            ->assertSee('Send again with a new link')->assertSee('Revoke');

        $manager = User::factory()->create(['user_role' => 'user,access-manage:example-app']);
        $this->grant($manager, 'example-app');
        $this->signIn($manager);
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('pending@example.test')->assertDontSee('Send again with a new link')->assertDontSee('Send invitation');

        $viewer = User::factory()->create(['user_role' => 'user,access-view:example-app']);
        $this->grant($viewer, 'example-app');
        $this->signIn($viewer);
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('pending@example.test')->assertDontSee('Send again with a new link')->assertDontSee('Send invitation');

        $stranger = User::factory()->create(['user_role' => 'user,access-view:other-app']);
        $this->grant($stranger, 'example-app');
        $this->signIn($stranger);
        $this->get('/applications/example-app/access')->assertForbidden();
    }

    public function test_invitation_visibility_follows_the_access_page_not_the_invite_role(): void
    {
        $permissions = app(DelegatedAccessPermissions::class);
        $user = fn (string $roles): User => new User(['user_role' => $roles]);

        $this->assertFalse($permissions->canSeeInvitations($user('user,access-invite:example-app'), 'example-app'));
        $this->assertTrue($permissions->canSeeInvitations($user('user,access-view:example-app'), 'example-app'));
        $this->assertTrue($permissions->canSeeInvitations($user('user,access-manage:*'), 'example-app'));
        $this->assertFalse($permissions->canSeeInvitations($user('user,access-view:other-app,access-invite:*'), 'example-app'));
    }

    public function test_every_pending_invitation_stays_listed_beyond_the_history_cap(): void
    {
        $this->confirm();
        $this->invite('still-pending@example.test')->assertSessionHas('invitation_notice');
        $template = (array) DB::table('access_invitations')->first();
        unset($template['id']);
        for ($i = 0; $i < 55; $i++) {
            DB::table('access_invitations')->insert([...$template, 'email' => "old-{$i}@example.test", 'email_normalized' => "old-{$i}@example.test",
                'token_hash' => hash('sha256', "old-{$i}"), 'pending_key' => null, 'revoked_at' => now(), 'revoked_by' => $this->inviter->id]);
        }

        $page = $this->get('/applications/example-app/access')->assertOk()->assertSee('still-pending@example.test');
        $this->assertSame(51, substr_count($page->getContent(), '@example.test</span>,'));
        $page->assertSee('old-54@example.test')->assertDontSee('old-4@example.test');
    }

    public function test_the_created_audit_row_records_no_workspace_or_role(): void
    {
        $this->confirm();
        $this->invite('person@example.test', access: ['application_admin' => '1', 'workspaces' => [
            ['id' => 'workspace-a', 'role' => 'sender'], ['id' => 'workspace-b', 'role' => 'auditor'],
        ]])->assertSessionHas('invitation_notice');

        $row = AuthAuditLog::query()->where('event', InvitationAudit::CREATED)->firstOrFail();
        $invitation = AccessInvitation::query()->firstOrFail();
        $this->assertSame(['invitation_id' => $invitation->id, 'application' => 'example-app', 'application_admin' => true, 'workspace_count' => 2], $row->metadata);
        foreach (['workspace-a', 'workspace-b', 'sender', 'auditor'] as $value) {
            $this->assertStringNotContainsString($value, (string) DB::table('auth_audit_log')->pluck('metadata')->implode(' '));
        }
    }

    public function test_an_account_created_through_a_handed_over_link_is_not_verified(): void
    {
        $this->confirm();
        Mail::swap(Mail::getFacadeRoot()->manager);
        config(['mail.default' => 'brevo', 'services.brevo.dsn' => null]);
        $sealed = $this->invite('person@example.test')->assertSessionHas('invitation_mail_failed', true)
            ->baseResponse->getSession()->get('invitation_link');
        $this->assertTrue(AccessInvitation::query()->firstOrFail()->link_handed_over);

        $person = $this->acceptAsNewPerson(parse_url(Crypt::decryptString($sealed), PHP_URL_PATH));

        $this->assertNull($person->email_verified_at);
        $this->assertTrue(AuthAuditLog::query()->where('event', InvitationAudit::ACCEPTED)->firstOrFail()->metadata['link_handed_over']);
    }

    public function test_a_successful_send_after_a_failed_one_marks_the_link_delivered(): void
    {
        $this->confirm();
        $fake = Mail::getFacadeRoot();
        Mail::swap($fake->manager);
        $default = config('mail.default');
        config(['mail.default' => 'brevo', 'services.brevo.dsn' => null]);
        $this->invite('person@example.test')->assertSessionHas('invitation_mail_failed', true);
        $invitation = AccessInvitation::query()->firstOrFail();

        Mail::swap($fake);
        config(['mail.default' => $default]);
        $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")->assertSessionHas('invitation_mail_failed', false);
        $this->assertFalse($invitation->fresh()->link_handed_over);

        $person = $this->acceptAsNewPerson($this->lastMailedLink());
        $this->assertNotNull($person->email_verified_at);
        $this->assertFalse(AuthAuditLog::query()->where('event', InvitationAudit::ACCEPTED)->firstOrFail()->metadata['link_handed_over']);
    }

    public function test_a_scoped_administrator_sees_and_controls_only_the_invitations_they_sent(): void
    {
        $other = User::factory()->create(['name' => 'Second Inviter', 'user_role' => 'user,access-manage:example-app,access-invite:example-app',
            'password' => Hash::make('current-password-example')]);
        $this->grant($other, 'example-app');
        $this->confirm();
        $this->invite('first-recipient@example.test')->assertSessionHas('invitation_notice');
        $this->signIn($other);
        $this->confirm();
        $this->invite('second-recipient@example.test')->assertSessionHas('invitation_notice');
        [$first, $second] = AccessInvitation::query()->orderBy('id')->get()->all();

        // The application reports neither as an application administrator.
        $this->applicationAdmin = false;
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('second-recipient@example.test')->assertDontSee('first-recipient@example.test');
        $this->post("/applications/example-app/access/invitations/{$first->id}/revoke")->assertNotFound();
        $this->post("/applications/example-app/access/invitations/{$first->id}/resend")->assertNotFound();
        $this->assertTrue($first->fresh()->isPending());
        $this->assertSame($this->inviter->id, $first->fresh()->inviter_id);

        $this->signIn($this->inviter);
        $this->confirm();
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('first-recipient@example.test')->assertDontSee('second-recipient@example.test');
        $this->post("/applications/example-app/access/invitations/{$second->id}/revoke")->assertNotFound();
        $this->assertTrue($second->fresh()->isPending());

        // An application-wide administrator sees and controls both.
        $this->applicationAdmin = true;
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('first-recipient@example.test')->assertSee('second-recipient@example.test');
        $this->post("/applications/example-app/access/invitations/{$second->id}/revoke")->assertSessionHas('invitation_notice');
        $this->assertSame(AccessInvitation::STATUS_REVOKED, $second->fresh()->status());
    }

    public function test_invitations_are_refused_while_the_mailer_does_not_deliver(): void
    {
        $this->confirm();
        $this->invite('person@example.test')->assertSessionHas('invitation_notice');
        $invitation = AccessInvitation::query()->firstOrFail();
        $hash = $invitation->token_hash;

        foreach (['log', 'array', 'failover'] as $mailer) {
            config(['mail.default' => $mailer]);
            $this->get('/applications/example-app/access')->assertOk()
                ->assertSee('Email is not configured to deliver on this provider')->assertDontSee('Send invitation');
            $this->invite('other@example.test')->assertSessionHasErrors('invitation');
            $this->post("/applications/example-app/access/invitations/{$invitation->id}/resend")->assertSessionHasErrors('invitation');
        }

        $this->assertSame(1, AccessInvitation::query()->count());
        $this->assertSame($hash, $invitation->fresh()->token_hash);
        Mail::assertSent(AccessInvitationMail::class, 1);
    }

    public function test_a_failed_email_still_answers_alike_and_shows_the_link(): void
    {
        $this->confirm();
        Mail::swap(Mail::getFacadeRoot()->manager);
        config(['mail.default' => 'brevo', 'services.brevo.dsn' => null]);

        $response = $this->invite('person@example.test')
            ->assertSessionHas('invitation_notice', 'Invitation sent.')
            ->assertSessionHas('invitation_mail_failed', true)
            ->assertSessionHas('invitation_link');
        // The session never holds the raw token: only an encryption of the link.
        $sealed = $response->baseResponse->getSession()->get('invitation_link');
        $link = Crypt::decryptString($sealed);
        $token = basename($link);
        $this->assertSame(hash('sha256', $token), AccessInvitation::query()->firstOrFail()->token_hash);
        $this->assertStringNotContainsString($token, json_encode($response->baseResponse->getSession()->all()));
        $this->get('/applications/example-app/access')->assertSee('could not be sent')->assertSee($link);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::SENT, 'succeeded' => false]);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::LINK_SHOWN]);
        $this->assertDatabaseHas('auth_audit_log', ['event' => InvitationAudit::CREATED, 'acting_user_id' => $this->inviter->id]);
    }

    private function fakeApplications(): void
    {
        Http::fake(function (ClientRequest $request) {
            $application = $request['application'];
            $operation = $request['operation'];
            $subject = $request['subject'] ?? null;
            $envelope = ['contract_version' => $this->contractVersion, 'application' => $application];
            $state = function (string $subject): array {
                $account = $this->accounts[$subject] ?? null;

                return ['subject' => $subject, 'provisioned' => $account !== null, 'revision' => $account['revision'] ?? null,
                    'access' => $account === null ? null : ['application_admin' => $account['application_admin'], 'workspaces' => $account['workspaces']],
                    'allowed_edits' => ['application_admin' => $account !== null, 'workspaces' => $account !== null, 'provision' => $account === null,
                        ...($this->contractVersion === 3 ? ['remove' => $account !== null] : [])]];
            };
            if ($operation === 'receipt') {
                $stored = $this->receipts[$request['operation_id']] ?? null;

                return Http::response([...$envelope, 'operation' => 'receipt', 'operation_id' => $request['operation_id'], ...($stored === null
                    ? ['status' => 'unknown'] : ['status' => 'known', 'response_status' => $stored['status'], 'response' => $stored['body']])]);
            }
            if ($operation === 'update') {
                if ($this->failUpdates) {
                    return Http::response(['error' => 'unavailable'], 503);
                }
                // Version 3: a repeat of the same operation is answered from its receipt, and the same
                // id on a different request is refused.
                $fingerprint = hash('sha256', json_encode(array_diff_key($request->data(), ['operation_id' => true])));
                if (isset($request['operation_id'], $this->receipts[$request['operation_id']])) {
                    $stored = $this->receipts[$request['operation_id']];

                    return $stored['fingerprint'] === $fingerprint
                        ? Http::response($stored['body'], $stored['status'])
                        : Http::response(['error' => 'invalid_request'], 422);
                }
                $answer = function (array $body, int $status) use ($request, $fingerprint) {
                    if (isset($request['operation_id'])) {
                        $this->receipts[$request['operation_id']] = ['fingerprint' => $fingerprint, 'status' => $status, 'body' => $body];
                    }

                    return Http::response($body, $status);
                };
                if ($this->refuseUpdates) {
                    return $answer(['error' => 'not_authorized'], 403);
                }
                $current = $this->accounts[$subject] ?? null;
                if (($request['expected_revision'] === null) !== ($current === null)
                    || ($current !== null && $current['revision'] !== $request['expected_revision'])) {
                    return $answer(['error' => 'revision_conflict'], 409);
                }
                $this->accounts[$subject] = ['application_admin' => $request['access']['application_admin'], 'revision' => 'revision-'.Str::random(6),
                    'workspaces' => array_map(fn (array $membership): array => [...$membership, 'editable' => true], $request['access']['workspaces'])];
                $response = $answer([...$envelope, 'operation' => 'update', ...$state($subject)], 200);

                return $this->loseUpdateAnswers ? Http::response(['error' => 'unavailable'], 503) : $response;
            }
            $data = match ($operation) {
                'capabilities' => ['controls' => ['application_admin' => $this->applicationAdmin, 'workspace_roles' => array_values(array_filter([
                    ['id' => 'owner', 'label' => 'Owner'], ['id' => 'admin', 'label' => 'Administrator'],
                    ['id' => 'sender', 'label' => 'Sender'], ['id' => 'auditor', 'label' => 'Auditor'],
                ], fn (array $role): bool => $this->advertisedRoles === null || in_array($role['id'], $this->advertisedRoles, true))), 'provisioning' => $this->provisioning]],
                'subjects' => ['subjects' => [], 'next_cursor' => null],
                'workspaces' => ['workspaces' => [
                    ['id' => 'workspace-a', 'label' => 'Workspace A'], ['id' => 'workspace-b', 'label' => 'Workspace B'],
                ], 'next_cursor' => null],
                default => $state($subject),
            };

            return Http::response([...$envelope, 'operation' => $operation, ...$data]);
        });
    }

    /** @return list<array<string, mixed>> the update requests sent, oldest first, with their headers */
    private function updates(): array
    {
        return Http::recorded(fn (ClientRequest $request): bool => ($request->data()['operation'] ?? null) === 'update')
            ->map(fn (array $pair): array => [...$pair[0]->data(), '_authorization' => $pair[0]->header('Authorization')[0]])
            ->values()->all();
    }

    /** @return array<string, mixed> */
    private function claims(array $update): array
    {
        $payload = explode('.', substr($update['_authorization'], strlen('Bearer ')))[1];

        return json_decode(base64_decode(strtr($payload, '-_', '+/')), true, flags: JSON_THROW_ON_ERROR);
    }

    private function invite(string $email, string $application = 'example-app', ?array $access = null): TestResponse
    {
        return $this->from("/applications/{$application}/access")->post("/applications/{$application}/access/invitations", [
            'email' => $email, ...($access ?? ['application_admin' => '0', 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]]),
        ]);
    }

    private function inviteAndGetLink(string $email, ?array $access = null): string
    {
        $this->invite($email, access: $access)->assertSessionMissing('invitation_link');

        return $this->lastMailedLink();
    }

    /** The link only the invited address receives. */
    private function lastMailedLink(): string
    {
        return parse_url(Mail::sent(AccessInvitationMail::class)->last()->link, PHP_URL_PATH);
    }

    private function inviteAndGetLinkAs(User $inviter, string $email): string
    {
        $this->signIn($inviter);
        $this->confirm();

        return $this->inviteAndGetLink($email);
    }

    private function acceptAsNewPerson(string $link): User
    {
        $this->signOutLocally();
        $this->post($link.'/accept', ['name' => 'Example Person', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example'])
            ->assertRedirect('/invitations/accepted');

        return User::query()->findOrFail(AccessInvitation::query()->where('token_hash', hash('sha256', basename($link)))->value('accepted_user_id'));
    }

    private function useVersion3(): void
    {
        $this->contractVersion = 3;
        config(['delegated-access.applications.example-app.contract_version' => 3, 'delegated-access.applications.other-app.contract_version' => 3]);
    }

    private function grant(User $user, string $application): void
    {
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $this->clients[$application]->id, 'subject' => $user->id,
            'created_at' => now(), 'updated_at' => now()]);
    }

    private function signIn(User $user): void
    {
        $this->actingAs($user)->withSession([EnsureCredentialVersion::SESSION_KEY => (int) $user->credential_version]);
    }

    private function signOutLocally(): void
    {
        Auth::logout();
        $this->flushSession();
    }

    private function confirm(string $application = 'example-app'): void
    {
        $this->post("/applications/{$application}/access/confirm", ['password' => 'current-password-example'])
            ->assertRedirect("/applications/{$application}/access");
    }

    /** Confirm where the roles allow reaching the page at all; inviting is refused either way. */
    private function confirmIfPossible(): void
    {
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example']);
    }
}
