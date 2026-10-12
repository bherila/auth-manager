<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Mail\AccessInvitationMail;
use App\Mail\InvitationCodeMail;
use App\Models\AccessInvitation;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\OAuth\ApplicationInvitationScopeRepository;
use App\Services\Invitations\AccessInvitationService;
use App\Services\Invitations\ApplicationActorAssertionVerifier;
use App\Services\Invitations\InvitationAudit;
use App\Support\ApplicationInvitationKeys;
use App\Support\ApplicationInvitations;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use DateTimeImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Once;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Tests\Fixtures\UsesDurableNonces;
use Tests\TestCase;

/**
 * Admission invitations an application requests for itself: who may call, what the caller learns,
 * isolation between applications and paths, rate limits, and what acceptance gives.
 */
class ApplicationInvitationTest extends TestCase
{
    use RefreshDatabase;
    use UsesDurableNonces;

    private const ISSUER = 'https://identity.example.test';

    private string $oauthKeyDirectory;

    /** @var array<string, string> private PEM by application */
    private array $privateKeys = [];

    /** @var array<string, string> public key file by application */
    private array $publicKeyPaths = [];

    /** @var array<string, PassportClient> */
    private array $clients = [];

    /** @var array<string, string> */
    private array $tokens = [];

    private User $actor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $this->setUpNonceStore();

        config()->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $this->oauthKeyDirectory = storage_path('framework/testing/oauth-'.Str::uuid());
        File::ensureDirectoryExists($this->oauthKeyDirectory, 0700);
        [$private, $public] = $this->keyPair();
        File::put($this->oauthKeyDirectory.'/oauth-private.key', $private);
        File::put($this->oauthKeyDirectory.'/oauth-public.key', $public);
        chmod($this->oauthKeyDirectory.'/oauth-private.key', 0600);
        chmod($this->oauthKeyDirectory.'/oauth-public.key', 0600);
        Passport::loadKeysFrom($this->oauthKeyDirectory);

        $keyEntries = [];
        foreach (['example-app' => 'Example Application', 'other-app' => 'Other Application'] as $key => $name) {
            [$this->privateKeys[$key], $publicKey] = $this->keyPair();
            $this->publicKeyPaths[$key] = $this->oauthKeyDirectory."/{$key}-public.pem";
            File::put($this->publicKeyPaths[$key], $publicKey);
            $keyEntries[] = "{$key}|{$key}-v1|".$this->publicKeyPaths[$key];
            $this->clients[$key] = PassportClient::create(['id' => (string) Str::uuid(), 'name' => "{$name} Client",
                'secret' => "{$key}-secret", 'grant_types' => ['authorization_code', 'refresh_token', 'client_credentials'],
                'redirect_uris' => ["https://{$key}.example.test/callback"], 'revoked' => false]);
            RegisteredApplication::create(['key' => $key, 'name' => $name, 'launch_url' => "https://{$key}.example.test", 'enabled' => true])
                ->clients()->attach($this->clients[$key]->id);
        }

        config([
            'auth-manager.issuer' => self::ISSUER,
            'application-invitations.applications' => ['example-app', 'other-app'],
            'application-invitations.keys_environment' => implode(',', $keyEntries),
            'application-invitations.nonce_connection' => 'delegated_nonce_test',
            'application-invitations.per_application_per_hour' => 100,
            'application-invitations.per_actor_per_hour' => 20,
            // The provider's own invitations stay off: an application's path does not need them.
            'delegated-access.invitations' => ['enabled' => false, 'expires_after_days' => 7, 'per_inviter_per_hour' => 20, 'per_recipient_per_day' => 5],
            'mail.default' => 'smtp',
        ]);
        Mail::fake();
        Http::preventStrayRequests();

        $this->actor = User::factory()->create(['name' => 'Example Manager', 'email' => 'manager@example.test', 'user_role' => 'user']);
        $this->grant($this->actor, 'example-app');
        $this->grant($this->actor, 'other-app');
    }

    protected function tearDown(): void
    {
        Passport::$keyPath = null;
        File::deleteDirectory($this->oauthKeyDirectory);
        $this->tearDownNonceStore();
        parent::tearDown();
    }

    public function test_the_flag_is_off_for_every_application_unless_listed(): void
    {
        $defaults = require config_path('application-invitations.php');
        $this->assertSame([], $defaults['applications']);
        // Unset or empty (as .env.example leaves it): no keys either way.
        $this->assertSame([], ApplicationInvitationKeys::parse($defaults['keys_environment']));

        config(['application-invitations.applications' => []]);
        $this->create('person@example.test')->assertForbidden()->assertJsonPath('error', 'application_not_enabled');
        config(['application-invitations.applications' => ['other-app']]);
        $this->create('person@example.test')->assertForbidden()->assertJsonPath('error', 'application_not_enabled');

        $this->assertSame(0, AccessInvitation::query()->count());
        Mail::assertNothingSent();
    }

    public function test_an_enabled_application_creates_an_admission_invitation_and_gets_its_link(): void
    {
        $response = $this->create('Person@Example.test')->assertCreated()
            ->assertHeader('Cache-Control', 'no-store, private');
        $this->assertSame(['id', 'status', 'expires_at', 'link', 'email_sent'], array_keys($response->json('invitation')));
        $response->assertJsonPath('invitation.status', 'pending')->assertJsonPath('invitation.email_sent', true);
        $this->assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $response->json('invitation.expires_at'));
        $this->assertMatchesRegularExpression('#/invitations/'.AccessInvitationService::TOKEN_PATTERN.'$#', $response->json('invitation.link'));

        $invitation = AccessInvitation::query()->sole();
        $this->assertSame($response->json('invitation.id'), $invitation->id);
        $this->assertSame('example-app', $invitation->application);
        $this->assertSame($this->clients['example-app']->id, $invitation->requesting_client_id);
        $this->assertSame(['application_admin' => false, 'workspaces' => []], $invitation->access);
        $this->assertSame($this->actor->id, $invitation->inviter_id);
        $this->assertTrue(now()->addDays(7)->diffInMinutes($invitation->expires_at, true) < 2);
        // The link went to the application as well as the address: opening it proves nothing.
        $this->assertTrue($invitation->link_handed_over);
        Mail::assertSent(AccessInvitationMail::class, fn (AccessInvitationMail $mail): bool => $mail->hasTo('Person@Example.test')
            && $mail->link === $response->json('invitation.link') && $mail->applicationName === 'Example Application');

        $created = AuthAuditLog::query()->where('event', InvitationAudit::CREATED)->sole();
        $this->assertSame($this->actor->id, $created->acting_user_id);
        $this->assertSame('application', $created->metadata['via']);
        $this->assertSame($this->clients['example-app']->id, $created->metadata['oauth_client_id']);
        $this->assertSame((string) $this->actor->id, $created->metadata['actor_subject']);
        $this->assertSame(0, $created->metadata['workspace_count']);
        $this->assertStringNotContainsString('example.test', json_encode($created->metadata));
    }

    public function test_the_answer_is_the_same_whether_or_not_the_address_has_an_account(): void
    {
        User::factory()->create(['email' => 'existing@example.test']);
        $existing = $this->create('existing@example.test')->assertCreated()->json('invitation');
        $unknown = $this->create('nobody@example.test')->assertCreated()->json('invitation');

        $shape = fn (array $invitation): array => ['keys' => array_keys($invitation), 'status' => $invitation['status'], 'email_sent' => $invitation['email_sent']];
        $this->assertSame($shape($existing), $shape($unknown));
        Mail::assertSent(AccessInvitationMail::class, 2);
    }

    public function test_the_access_token_must_be_a_client_credentials_token_with_the_dedicated_scope(): void
    {
        $this->create('person@example.test', token: '')->assertUnauthorized()->assertJsonPath('error', 'invalid_token');
        $this->create('person@example.test', token: 'not-a-token')->assertUnauthorized()->assertJsonPath('error', 'invalid_token');

        $unscoped = $this->issueToken('example-app', scope: '');
        $this->create('person@example.test', token: $unscoped)->assertForbidden()->assertJsonPath('error', 'insufficient_scope');

        // A person's token: the stored token names someone.
        $token = $this->issueToken('example-app');
        DB::table('oauth_access_tokens')->update(['user_id' => $this->actor->id]);
        $this->create('person@example.test', token: $token)->assertUnauthorized()->assertJsonPath('error', 'invalid_token');

        // A client without the client credentials grant gets no token at all.
        $this->clients['example-app']->forceFill(['grant_types' => ['authorization_code']])->save();
        Once::flush(); // Passport memoizes client lookups for the life of the test's application.
        $this->post('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $this->clients['example-app']->id,
            'client_secret' => 'example-app-secret', 'scope' => ApplicationInvitations::SCOPE])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');

        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_the_scope_is_never_offered_outside_a_client_credentials_token(): void
    {
        $repository = app(ApplicationInvitationScopeRepository::class);
        $this->assertNull($repository->getScopeEntityByIdentifier(ApplicationInvitations::SCOPE));
        $this->assertNotNull($repository->getScopeEntityByIdentifier('identity:read'));

        $client = new BridgeClient($this->clients['example-app']->id, 'Example', [], true, null, ['authorization_code', 'client_credentials']);
        $scopes = [new Scope(ApplicationInvitations::SCOPE), new Scope('identity:read')];
        $ids = fn (array $finalized): array => array_map(fn ($scope): string => $scope->getIdentifier(), $finalized);
        $this->assertSame(['identity:read'], $ids($repository->finalizeScopes($scopes, 'authorization_code', $client, (string) $this->actor->id)));
        $this->assertSame(['identity:read'], $ids($repository->finalizeScopes($scopes, 'refresh_token', $client, (string) $this->actor->id)));
        $this->assertSame([ApplicationInvitations::SCOPE, 'identity:read'], $ids($repository->finalizeScopes($scopes, 'client_credentials', $client)));
        // Never advertised or offered to people: it is not in the profile's catalog.
        $this->assertArrayNotHasKey(ApplicationInvitations::SCOPE, (array) config('bherila-auth.oauth_server.scopes'));
    }

    public function test_the_calling_client_must_be_an_enabled_registrations_confidential_sign_in_client_with_a_key(): void
    {
        $token = $this->token('example-app');
        RegisteredApplication::query()->where('key', 'example-app')->update(['enabled' => false]);
        $this->create('person@example.test', token: $token)->assertForbidden()->assertJsonPath('error', 'application_not_enabled');
        RegisteredApplication::query()->where('key', 'example-app')->update(['enabled' => true]);

        config(['application-invitations.keys_environment' => 'other-app|other-app-v1|'.$this->publicKeyPaths['other-app']]);
        $this->create('person@example.test', token: $token)->assertForbidden()->assertJsonPath('error', 'application_not_enabled');

        config(['application-invitations.keys_environment' => 'example-app|v1|relative/path.pem']);
        $this->create('person@example.test', token: $token)->assertStatus(503)->assertJsonPath('error', 'invalid_configuration');

        // A client of no registration.
        $stray = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Stray', 'secret' => 'stray-secret',
            'grant_types' => ['authorization_code', 'client_credentials'], 'redirect_uris' => ['https://stray.example.test/callback'], 'revoked' => false]);
        $this->clients['stray'] = $stray;
        $this->privateKeys['stray'] = $this->privateKeys['example-app'];
        config(['application-invitations.keys_environment' => 'example-app|example-app-v1|'.$this->publicKeyPaths['example-app']]);
        $this->create('person@example.test', application: 'stray', keyId: 'example-app-v1')->assertForbidden()->assertJsonPath('error', 'application_not_enabled');

        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_the_actor_assertion_must_be_the_applications_own_for_this_exact_request(): void
    {
        $body = json_encode(['email' => 'person@example.test']);
        $url = self::ISSUER.'/api/application-invitations';
        $refusals = [
            'missing' => null,
            'signed with another application\'s key' => $this->assertion(['body' => $body, 'key' => $this->privateKeys['other-app']]),
            'issued by another client' => $this->assertion(['body' => $body, 'iss' => $this->clients['other-app']->id]),
            'for another endpoint' => $this->assertion(['body' => $body, 'aud' => $url.'/1/revoke']),
            'for another body' => $this->assertion(['body' => json_encode(['email' => 'someone@example.test'])]),
            'the provider\'s own kind' => $this->assertion(['body' => $body, 'typ' => 'application-access+jwt']),
            'unknown key id' => $this->assertion(['body' => $body, 'kid' => 'unknown-v1']),
            'expired' => $this->assertion(['body' => $body, 'iat' => time() - 120, 'exp' => time() - 60]),
            'living too long' => $this->assertion(['body' => $body, 'exp' => time() + 120]),
            'non-canonical subject' => $this->assertion(['body' => $body, 'sub' => '0'.$this->actor->id]),
            'extra claim' => $this->assertion(['body' => $body, 'extra' => ['roles' => ['admin']]]),
        ];
        foreach ($refusals as $case => $assertion) {
            $this->send('/api/application-invitations', $body, assertion: $assertion ?? '')
                ->assertUnauthorized()->assertJsonPath('error', 'invalid_actor_assertion');
        }

        $assertion = $this->assertion(['body' => $body]);
        $this->send('/api/application-invitations', $body, assertion: $assertion)->assertCreated();
        $this->send('/api/application-invitations', $body, assertion: $assertion)
            ->assertUnauthorized()->assertJsonPath('error', 'replayed_actor_assertion');
        $this->assertSame(1, AccessInvitation::query()->count());
    }

    public function test_used_assertion_ids_need_durable_storage(): void
    {
        // The default test connection is in-memory and inside the test's transaction.
        config(['application-invitations.nonce_connection' => null]);
        $this->create('person@example.test')->assertStatus(503)->assertJsonPath('error', 'replay_storage_unavailable');
        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_the_nonce_table_is_created_on_the_configured_connection_and_kept_on_rollback(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'synthetic-nonce-migration-');
        config(['database.connections.nonce_migration_test' => ['driver' => 'sqlite', 'database' => $path, 'prefix' => ''],
            'application-invitations.nonce_connection' => 'nonce_migration_test']);
        try {
            $migration = require database_path('migrations/2026_10_12_000100_create_delegated_nonces_table.php');
            $migration->up();
            $migration->up();
            $this->assertTrue(Schema::connection('nonce_migration_test')->hasTable(DatabaseNonceStore::TABLE));
            $this->assertTrue((new DatabaseNonceStore(DB::connection('nonce_migration_test')))->consume(str_repeat('a', 64), 60));

            // Rolling back never drops replay history, here or on a table that predates the migration.
            $migration->down();
            $this->assertTrue(Schema::connection('nonce_migration_test')->hasTable(DatabaseNonceStore::TABLE));
            $this->assertFalse((new DatabaseNonceStore(DB::connection('nonce_migration_test')))->consume(str_repeat('a', 64), 60));
        } finally {
            DB::purge('nonce_migration_test');
            @unlink($path);
        }
    }

    public function test_the_actor_must_be_an_active_account_with_a_grant_to_the_calling_client(): void
    {
        $ungranted = User::factory()->create(['email' => 'ungranted@example.test']);
        $this->create('person@example.test', actor: $ungranted)->assertForbidden()->assertJsonPath('error', 'actor_not_eligible');
        $this->create('person@example.test', actor: (string) (User::query()->max('id') + 100))->assertForbidden()->assertJsonPath('error', 'actor_not_eligible');

        $disabled = User::factory()->create(['email' => 'disabled@example.test', 'disabled_at' => now()]);
        $this->grant($disabled, 'example-app');
        $this->create('person@example.test', actor: $disabled)->assertForbidden()->assertJsonPath('error', 'actor_not_eligible');

        // A grant to another application's client does not do.
        $elsewhere = User::factory()->create(['email' => 'elsewhere@example.test']);
        $this->grant($elsewhere, 'other-app');
        $this->create('person@example.test', actor: $elsewhere)->assertForbidden()->assertJsonPath('error', 'actor_not_eligible');

        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_the_body_is_an_email_and_nothing_else(): void
    {
        $this->send('/api/application-invitations', json_encode(['email' => 'person@example.test', 'roles' => ['admin']]))
            ->assertStatus(422)->assertJsonPath('error', 'invalid_request')->assertJsonStructure(['errors' => ['roles']]);
        $this->send('/api/application-invitations', json_encode(['email' => 'not an address']))
            ->assertStatus(422)->assertJsonPath('error', 'invalid_request')->assertJsonStructure(['errors' => ['email']]);
        $this->send('/api/application-invitations', json_encode(['person@example.test']))->assertStatus(422);
        $this->send('/api/application-invitations', 'email=person@example.test')->assertStatus(422);

        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_invitations_need_a_delivering_mailer(): void
    {
        config(['mail.default' => 'log']);
        $this->create('person@example.test')->assertStatus(503)->assertJsonPath('error', 'mail_unavailable');
        $this->assertSame(0, AccessInvitation::query()->count());
    }

    public function test_a_new_invitation_supersedes_the_applications_earlier_one_but_not_another_paths(): void
    {
        $fromPages = $this->pagesInvitation('person@example.test');
        $first = $this->create('person@example.test')->json('invitation');
        $second = $this->create('PERSON@example.test')->json('invitation');

        $this->assertSame(AccessInvitation::STATUS_REVOKED, AccessInvitation::query()->find($first['id'])->status());
        $this->assertSame(AccessInvitation::STATUS_PENDING, AccessInvitation::query()->find($second['id'])->status());
        $this->assertSame(AccessInvitation::STATUS_PENDING, $fromPages->fresh()->status());
        $superseded = AuthAuditLog::query()->where('event', InvitationAudit::REVOKED)->sole();
        $this->assertSame('superseded', $superseded->metadata['reason']);
        $this->assertSame($first['id'], $superseded->metadata['invitation_id']);

        // Another application's request supersedes nothing here.
        $this->create('person@example.test', application: 'other-app')->assertCreated();
        $this->assertSame(AccessInvitation::STATUS_PENDING, AccessInvitation::query()->find($second['id'])->status());

        $this->get($this->path($first['link']))->assertNotFound();
    }

    public function test_resend_replaces_the_token_and_the_old_link_stops_working(): void
    {
        $created = $this->create('person@example.test')->json('invitation');
        $this->travel(2)->days();
        $resent = $this->action($created['id'], 'resend')->assertOk()->json('invitation');

        $this->assertSame($created['id'], $resent['id']);
        $this->assertNotSame($created['link'], $resent['link']);
        $this->assertTrue(now()->addDays(7)->diffInMinutes(AccessInvitation::query()->find($created['id'])->expires_at, true) < 2);
        $this->get($this->path($created['link']))->assertNotFound();
        $this->get($this->path($resent['link']))->assertOk();
        Mail::assertSent(AccessInvitationMail::class, 2);
        $audit = AuthAuditLog::query()->where('event', InvitationAudit::RESENT)->sole();
        $this->assertSame($this->clients['example-app']->id, $audit->metadata['oauth_client_id']);

        $this->action($created['id'], 'revoke')->assertOk();
        $this->action($created['id'], 'resend')->assertStatus(409)->assertJsonPath('error', 'invitation_not_pending');
    }

    public function test_revoke_stops_the_link_and_is_idempotent_but_an_accepted_invitation_stays(): void
    {
        $created = $this->create('person@example.test')->json('invitation');
        $this->action($created['id'], 'revoke')->assertOk()->assertExactJson(['invitation' => ['id' => $created['id'], 'status' => 'revoked']]);
        $this->action($created['id'], 'revoke')->assertOk()->assertJsonPath('invitation.status', 'revoked');
        $this->get($this->path($created['link']))->assertNotFound();
        $this->assertSame(1, AuthAuditLog::query()->where('event', InvitationAudit::REVOKED)->count());

        $accepted = $this->create('other@example.test')->json('invitation');
        $this->acceptAsNewPerson($accepted['link']);
        $this->action($accepted['id'], 'revoke')->assertStatus(409)->assertJsonPath('error', 'invitation_accepted');
    }

    public function test_an_application_reaches_only_invitations_requested_through_its_own_client(): void
    {
        $mine = $this->create('person@example.test')->json('invitation');
        $fromPages = $this->pagesInvitation('person@example.test');

        foreach ([$mine['id'], $fromPages->id, 999999] as $id) {
            foreach (['resend', 'revoke'] as $action) {
                $this->action($id, $action, application: 'other-app')->assertNotFound()->assertJsonPath('error', 'invitation_not_found');
            }
        }
        foreach (['resend', 'revoke'] as $action) {
            $this->action($fromPages->id, $action)->assertNotFound()->assertJsonPath('error', 'invitation_not_found');
        }
        $this->assertSame(AccessInvitation::STATUS_PENDING, AccessInvitation::query()->find($mine['id'])->status());
        $this->assertSame(AccessInvitation::STATUS_PENDING, $fromPages->fresh()->status());

        // And the provider's own pages never reach an application's invitation.
        $this->expectException(NotFoundHttpException::class);
        app(AccessInvitationService::class)->revoke(Request::create('/'), $this->actor, AccessInvitation::query()->find($mine['id']));
    }

    public function test_accepting_creates_the_account_and_grants_the_requesting_client_alone(): void
    {
        // A second sign-in client of the same application is not admitted to.
        $second = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Second Client', 'secret' => 'second-secret',
            'grant_types' => ['authorization_code'], 'redirect_uris' => ['https://second.example.test/callback'], 'revoked' => false]);
        RegisteredApplication::query()->where('key', 'example-app')->sole()->clients()->attach($second->id);

        $created = $this->create('person@example.test')->json('invitation');
        $this->acceptAsNewPerson($created['link'])->assertRedirect('/invitations/accepted');

        $person = User::query()->where('email', 'person@example.test')->sole();
        // Created only with the code emailed to the address, so the address is proven.
        $this->assertNotNull($person->email_verified_at);
        $this->assertSame([$this->clients['example-app']->id], DB::table('oauth_client_grants')->where('subject', $person->id)->pluck('oauth_client_id')->all());
        $this->assertSame('user', $person->user_role);
        // No delegated access call: nothing to apply (stray requests would fail the test).
        Http::assertNothingSent();
        $invitation = AccessInvitation::query()->find($created['id']);
        $this->assertSame(AccessInvitation::STATUS_ACCEPTED, $invitation->status());
        $this->assertNull($invitation->roles_status);

        $accepted = AuthAuditLog::query()->where('event', InvitationAudit::ACCEPTED)->sole();
        $this->assertSame([$this->clients['example-app']->id], $accepted->metadata['oauth_client_ids']);
        $this->assertSame('application', $accepted->metadata['via']);
        $this->assertSame((string) $this->actor->id, $accepted->metadata['actor_subject']);
        $this->assertTrue($accepted->metadata['link_returned']);
        $this->assertTrue($accepted->metadata['account_created']);
        $this->get('/invitations/accepted')->assertOk()->assertDontSee('could not be set up yet');
    }

    public function test_an_existing_account_signs_in_and_accepts(): void
    {
        $person = User::factory()->create(['email' => 'person@example.test', 'password' => Hash::make('person-password-example')]);
        $created = $this->create('Person@example.test')->json('invitation');

        $this->actingAs($person)->withSession([EnsureCredentialVersion::SESSION_KEY => (int) $person->credential_version]);
        $this->get($this->path($created['link']))->assertOk()->assertSee('Accept invitation');
        $this->post($this->path($created['link']).'/accept')->assertRedirect('/invitations/accepted');

        $this->assertSame([$this->clients['example-app']->id], DB::table('oauth_client_grants')->where('subject', $person->id)->pluck('oauth_client_id')->all());
        // Immediate, as before: no code asked for or sent.
        Mail::assertNotSent(InvitationCodeMail::class);
    }

    public function test_creating_an_account_from_an_applications_link_needs_the_code_emailed_to_the_address(): void
    {
        $created = $this->create('Person@example.test')->json('invitation');
        $link = $this->path($created['link']);

        // Before any code: no way to create the account, with or without a guess.
        $this->get($link)->assertOk()->assertSee('Email me a code')->assertDontSee('Create account and accept');
        $this->post($link.'/accept', $this->newPerson())->assertRedirect($link)->assertSessionHasErrors('code');
        $this->post($link.'/accept', $this->newPerson('000000'))->assertRedirect($link)->assertSessionHasErrors('code');
        $this->assertSame(0, User::query()->where('email', 'Person@example.test')->count());

        $this->post($link.'/code')->assertRedirect($link)->assertSessionHas('invitation_code_sent');
        Mail::assertSent(InvitationCodeMail::class, 1);
        $mail = Mail::sent(InvitationCodeMail::class)->sole();
        $this->assertTrue($mail->hasTo('Person@example.test'));
        $this->assertSame('Example Application', $mail->applicationName);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $mail->code);
        $body = $mail->render();
        $this->assertStringContainsString($mail->code, $body);
        $this->assertStringNotContainsString('/invitations/', $body);
        $this->get($link)->assertOk()->assertSee('Create account and accept')->assertDontSee($mail->code);

        $invitation = AccessInvitation::query()->find($created['id']);
        $this->assertNotNull($invitation->verification_code_hash);
        $this->assertStringNotContainsString($mail->code, $invitation->verification_code_hash);
        $sent = AuthAuditLog::query()->where('event', InvitationAudit::CODE_SENT)->sole();
        $this->assertTrue($sent->succeeded);
        $this->assertNull($sent->acting_user_id);
        $this->assertSame('application', $sent->metadata['via']);
        $this->assertSame($this->clients['example-app']->id, $sent->metadata['oauth_client_id']);
        $this->assertStringNotContainsString('example.test', json_encode($sent->metadata));
        $this->assertStringNotContainsString($mail->code, json_encode($sent->metadata));

        $this->post($link.'/accept', $this->newPerson($mail->code))->assertRedirect('/invitations/accepted');
        $person = User::query()->where('email', 'Person@example.test')->sole();
        $this->assertNotNull($person->email_verified_at);
        $this->assertAuthenticatedAs($person);
        $this->assertSame([$this->clients['example-app']->id], DB::table('oauth_client_grants')->where('subject', $person->id)->pluck('oauth_client_id')->all());
        $this->assertTrue(AuthAuditLog::query()->where('event', InvitationAudit::ACCEPTED)->sole()->metadata['address_verified']);
        $this->assertNull(AccessInvitation::query()->find($created['id'])->verification_code_hash);

        // Spent: the same link and code create nothing more.
        $this->post('/logout');
        $this->post($link.'/accept', $this->newPerson($mail->code))->assertNotFound();
        $this->assertSame(1, User::query()->where('email', 'Person@example.test')->count());
    }

    public function test_wrong_expired_and_exhausted_codes_are_rejected_with_bounded_attempts(): void
    {
        $created = $this->create('person@example.test')->json('invitation');
        $link = $this->path($created['link']);
        $code = $this->requestCode($link);
        $wrong = $code === '123456' ? '654321' : '123456';

        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $this->post($link.'/accept', $this->newPerson($wrong))->assertRedirect($link)->assertSessionHasErrors('code');
        }
        // The fifth wrong code spent this one: even the right code no longer works.
        $this->post($link.'/accept', $this->newPerson($code))->assertRedirect($link)->assertSessionHasErrors('code');
        $this->get($link)->assertOk()->assertSee('Email me a code');
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
        $rejected = AuthAuditLog::query()->where('event', InvitationAudit::CODE_REJECTED)->orderBy('id')->get();
        $this->assertSame(['incorrect', 'incorrect', 'incorrect', 'incorrect', 'exhausted', 'missing'], $rejected->pluck('metadata.reason')->all());
        $this->assertFalse($rejected->first()->succeeded);

        // A code expires.
        $expiring = $this->requestCode($link);
        $this->travel(16)->minutes();
        $this->post($link.'/accept', $this->newPerson($expiring))->assertRedirect($link)->assertSessionHasErrors('code');
        $this->assertSame('expired', AuthAuditLog::query()->where('event', InvitationAudit::CODE_REJECTED)->latest('id')->first()->metadata['reason']);
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());

        // A new code still works after both.
        $this->post($link.'/accept', $this->newPerson($this->requestCode($link)))->assertRedirect('/invitations/accepted');
        $this->assertNotNull(User::query()->where('email', 'person@example.test')->sole()->email_verified_at);
    }

    public function test_a_code_is_bound_to_its_invitation_and_its_current_link(): void
    {
        $mine = $this->create('person@example.test')->json('invitation');
        $other = $this->create('person@example.test', application: 'other-app')->json('invitation');
        $mineCode = $this->requestCode($this->path($mine['link']));
        $otherCode = $this->requestCode($this->path($other['link']));
        if ($otherCode === $mineCode) {
            // One chance in a million; a second send gives a different code.
            $otherCode = $this->requestCode($this->path($other['link']));
        }
        $this->assertNotNull($mineCode);
        $this->assertNotSame($mineCode, $otherCode);

        // Another invitation's code, for the same address, does not work here.
        $this->post($this->path($mine['link']).'/accept', $this->newPerson($otherCode))->assertSessionHasErrors('code');
        $this->post($this->path($other['link']).'/accept', $this->newPerson($mineCode))->assertSessionHasErrors('code');

        // A resend replaces the link and drops its code.
        $resent = $this->action($mine['id'], 'resend')->assertOk()->json('invitation');
        $this->assertNull(AccessInvitation::query()->find($mine['id'])->verification_code_hash);
        $this->post($this->path($resent['link']).'/accept', $this->newPerson($mineCode))->assertSessionHasErrors('code');
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
    }

    public function test_code_sends_are_bounded_and_fail_closed_without_mail(): void
    {
        config(['application-invitations.verification.max_sends' => 2, 'application-invitations.verification.per_address_per_hour' => 3]);
        $first = $this->path($this->create('person@example.test')->json('invitation.link'));
        $this->requestCode($first);
        $this->requestCode($first);
        $this->post($first.'/code')->assertRedirect($first)->assertSessionHas('invitation_error');
        Mail::assertSent(InvitationCodeMail::class, 2);

        // Per address, across invitations.
        $second = $this->path($this->create('person@example.test', application: 'other-app')->json('invitation.link'));
        $this->requestCode($second);
        $this->post($second.'/code')->assertSessionHas('invitation_error');
        Mail::assertSent(InvitationCodeMail::class, 3);
        $refusals = AuthAuditLog::query()->where('event', InvitationAudit::CODE_SENT)->where('succeeded', false)->orderBy('id')->get()->pluck('metadata.reason')->all();
        $this->assertSame(['send_limit', 'rate_limited'], $refusals);

        // No delivering mailer: no code, so no account.
        config(['application-invitations.verification.max_sends' => 5, 'application-invitations.verification.per_address_per_hour' => 50]);
        $third = $this->create('third@example.test')->json('invitation');
        config(['mail.default' => 'log']);
        $this->post($this->path($third['link']).'/code')->assertSessionHas('invitation_error');
        $this->assertNull(AccessInvitation::query()->find($third['id'])->verification_code_hash);

        // A transport failure leaves no usable code either.
        Mail::swap(Mail::getFacadeRoot()->manager);
        config(['mail.default' => 'brevo', 'services.brevo.dsn' => null]);
        $this->post($this->path($third['link']).'/code')->assertSessionHas('invitation_error');
        $this->assertNull(AccessInvitation::query()->find($third['id'])->verification_code_hash);
        $this->assertSame(['mail_unavailable', 'delivery_failed'], AuthAuditLog::query()->where('event', InvitationAudit::CODE_SENT)
            ->where('succeeded', false)->orderBy('id')->get()->pluck('metadata.reason')->slice(2)->values()->all());
        $this->assertSame(0, User::query()->where('email', 'third@example.test')->count());
    }

    public function test_the_application_holding_the_link_alone_cannot_create_the_account(): void
    {
        // Everything the application can do: create, resend, open the link, ask for codes and guess.
        $created = $this->create('person@example.test')->json('invitation');
        $resent = $this->action($created['id'], 'resend')->assertOk();
        $link = $this->path($resent->json('invitation.link'));
        $asked = $this->post($link.'/code');
        $code = Mail::sent(InvitationCodeMail::class)->sole()->code;
        foreach ([$resent, $asked, $this->get($link)] as $response) {
            $this->assertStringNotContainsString($code, (string) $response->getContent());
        }
        $this->assertStringNotContainsString($code, (string) json_encode(session()->all()));
        Mail::assertSent(InvitationCodeMail::class, fn (InvitationCodeMail $mail): bool => $mail->hasTo('person@example.test') && count($mail->to) === 1);

        foreach (['000000', '111111', '222222', '333333', '444444', '555555'] as $guess) {
            if ($guess !== $code) {
                $this->post($link.'/accept', $this->newPerson($guess));
            }
        }
        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
        $this->assertSame(AccessInvitation::STATUS_PENDING, AccessInvitation::query()->find($created['id'])->status());
    }

    public function test_an_existing_account_and_the_providers_own_invitations_need_no_code(): void
    {
        // An existing account: no code is offered or sent, signed in or not.
        User::factory()->create(['email' => 'existing@example.test']);
        $existing = $this->path($this->create('existing@example.test')->json('invitation.link'));
        $this->get($existing)->assertOk()->assertDontSee('Email me a code');
        $this->post($existing.'/code')->assertRedirect($existing);

        // The provider's own invitations keep creating accounts as before.
        config(['delegated-access.invitations.enabled' => true]);
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $fromPages = $this->pagesInvitation('person@example.test', $token);
        $fromPages->forceFill(['link_handed_over' => false, 'access' => ['application_admin' => false, 'workspaces' => []]])->save();
        $this->get("/invitations/{$token}")->assertOk()->assertSee('Create account and accept')->assertDontSee('Email me a code');
        $this->post("/invitations/{$token}/code")->assertRedirect("/invitations/{$token}");
        Mail::assertNotSent(InvitationCodeMail::class);
        $this->post("/invitations/{$token}/accept", $this->newPerson())->assertRedirect('/invitations/accepted');
        $this->assertNotNull(User::query()->where('email', 'person@example.test')->sole()->email_verified_at);
        $this->assertSame(0, AuthAuditLog::query()->whereIn('event', [InvitationAudit::CODE_SENT, InvitationAudit::CODE_REJECTED])->count());
    }

    public function test_a_link_stops_admitting_when_the_application_is_switched_off_or_loses_its_client(): void
    {
        $created = $this->create('person@example.test')->json('invitation');

        config(['application-invitations.applications' => ['other-app']]);
        $this->get($this->path($created['link']))->assertNotFound();
        $this->acceptAsNewPerson($created['link'])->assertNotFound();

        config(['application-invitations.applications' => ['example-app']]);
        RegisteredApplication::query()->where('key', 'example-app')->sole()->clients()->detach($this->clients['example-app']->id);
        $this->get($this->path($created['link']))->assertNotFound();

        $this->assertSame(0, User::query()->where('email', 'person@example.test')->count());
        $this->assertSame(0, DB::table('oauth_client_grants')->where('oauth_client_id', $this->clients['example-app']->id)->where('subject', '!=', $this->actor->id)->count());
    }

    public function test_rate_limits_per_actor_per_application_and_per_recipient(): void
    {
        config(['application-invitations.per_actor_per_hour' => 2]);
        $this->create('one@example.test')->assertCreated();
        $this->create('two@example.test')->assertCreated();
        $this->create('three@example.test')->assertStatus(429)->assertJsonPath('error', 'rate_limited')
            ->assertJsonPath('limit', 'actor')->assertHeader('Retry-After');

        config(['application-invitations.per_actor_per_hour' => 100, 'application-invitations.per_application_per_hour' => 3]);
        $colleague = User::factory()->create(['email' => 'colleague@example.test']);
        $this->grant($colleague, 'example-app');
        $this->create('three@example.test', actor: $colleague)->assertCreated();
        $this->create('four@example.test', actor: $colleague)->assertStatus(429)->assertJsonPath('limit', 'application');
        // Another application has its own budget.
        $this->create('four@example.test', application: 'other-app')->assertCreated();

        config(['application-invitations.per_application_per_hour' => 100, 'delegated-access.invitations.per_recipient_per_day' => 2]);
        $this->create('four@example.test', application: 'other-app')->assertCreated();
        $this->create('four@example.test')->assertStatus(429)->assertJsonPath('limit', 'recipient');

        // A resend sends mail, so it counts too.
        $created = AccessInvitation::query()->where('email', 'one@example.test')->sole();
        config(['delegated-access.invitations.per_recipient_per_day' => 1]);
        $this->action($created->id, 'resend')->assertStatus(429)->assertJsonPath('limit', 'recipient');

        $this->assertSame(5, AccessInvitation::query()->count());
    }

    public function test_the_operator_command_shows_readiness_and_toggles_client_credentials_on_sign_in_clients_only(): void
    {
        $public = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Public Client', 'secret' => null,
            'grant_types' => ['authorization_code'], 'redirect_uris' => ['https://public.example.test/callback'], 'revoked' => false]);
        RegisteredApplication::query()->where('key', 'example-app')->sole()->clients()->attach($public->id);
        $this->clients['example-app']->forceFill(['grant_types' => ['authorization_code', 'refresh_token']])->save();

        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app'])
            ->expectsOutputToContain('example-app-v1')->assertSuccessful();
        $this->assertSame(['authorization_code', 'refresh_token'], $this->clients['example-app']->fresh()->grant_types);

        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app', '--allow-client-credentials' => true])->assertSuccessful();
        $this->assertSame(['authorization_code', 'refresh_token', 'client_credentials'], $this->clients['example-app']->fresh()->grant_types);
        $this->assertSame(['authorization_code'], $public->fresh()->grant_types);
        $this->assertSame(1, AuthAuditLog::query()->where('event', 'application_invitation_client_credentials_allowed')->count());

        $client = $this->clients['example-app'];
        $row = fn (string $scopeCeiling, string $ready): array => ["{$client->name} ({$client->id})", 'yes', 'yes', $scopeCeiling, $ready];
        $headers = ['OAuth client', 'Confidential sign-in client', 'Client credentials', 'Scope ceiling allows '.ApplicationInvitations::SCOPE, 'Can request invitations'];
        $publicRow = ["Example Public Client ({$public->id})", 'no', 'no', 'yes', 'no'];
        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app'])->expectsTable($headers, [$row('yes', 'yes'), $publicRow])->assertSuccessful();
        // A stored scope ceiling without the invitation scope: Passport would drop it from the token.
        $client->forceFill(['scopes' => ['identity:read']])->save();
        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app'])->expectsTable($headers, [$row('no', 'no'), $publicRow])->assertSuccessful();
        $client->forceFill(['scopes' => ['identity:read', ApplicationInvitations::SCOPE]])->save();
        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app'])->expectsTable($headers, [$row('yes', 'yes'), $publicRow])->assertSuccessful();

        // A listed key file that is missing or not a public key cannot verify anything.
        File::put($this->oauthKeyDirectory.'/not-a-key.pem', 'not a key');
        foreach (['missing' => $this->oauthKeyDirectory.'/missing.pem', 'not a key' => $this->oauthKeyDirectory.'/not-a-key.pem'] as $path) {
            config(['application-invitations.keys_environment' => "example-app|example-app-v1|{$path}"]);
            $this->artisan('auth-manager:application-invitations', ['key' => 'example-app'])
                ->expectsOutputToContain('not a readable public key')->expectsTable($headers, [$row('yes', 'no'), $publicRow])->assertSuccessful();
            $this->create('person@example.test')->assertStatus(503)->assertJsonPath('error', 'invalid_configuration');
        }

        $this->artisan('auth-manager:application-invitations', ['key' => 'example-app', '--remove-client-credentials' => true])->assertSuccessful();
        $this->assertSame(['authorization_code', 'refresh_token'], $this->clients['example-app']->fresh()->grant_types);
        $this->artisan('auth-manager:application-invitations', ['key' => 'missing-app'])->assertFailed();
    }

    // ---------------------------------------------------------------------------------------------

    private function create(string $email, string $application = 'example-app', User|string|null $actor = null, ?string $token = null, ?string $keyId = null): TestResponse
    {
        $body = json_encode(['email' => $email]);

        return $this->send('/api/application-invitations', $body, $application, $actor, $token, keyId: $keyId);
    }

    private function action(int $id, string $action, string $application = 'example-app'): TestResponse
    {
        return $this->send("/api/application-invitations/{$id}/{$action}", '{}', $application);
    }

    /**
     * POST exactly this body, as the package client would: a client credentials token and an actor
     * assertion over the exact URL and body.
     */
    private function send(string $path, string $body, string $application = 'example-app', User|string|null $actor = null, ?string $token = null, ?string $assertion = null, ?string $keyId = null): TestResponse
    {
        $assertion ??= $this->assertion(['body' => $body, 'aud' => self::ISSUER.$path, 'sub' => $actor === null ? null : (string) ($actor instanceof User ? $actor->id : $actor)], $application, $keyId);
        $token ??= $this->token($application);
        $headers = ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'];
        if ($token !== '') {
            $headers['HTTP_AUTHORIZATION'] = 'Bearer '.$token;
        }
        if ($assertion !== '') {
            $headers['HTTP_ACTOR_ASSERTION'] = $assertion;
        }

        return $this->call('POST', $path, [], [], [], $headers, $body);
    }

    /** @param array<string, mixed> $claims */
    private function assertion(array $claims = [], string $application = 'example-app', ?string $keyId = null): string
    {
        $now = time();
        $iat = $claims['iat'] ?? $now;
        $builder = Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
            ->withHeader('typ', $claims['typ'] ?? ApplicationActorAssertionVerifier::TYPE)
            ->withHeader('kid', $claims['kid'] ?? $keyId ?? "{$application}-v1")
            ->issuedBy($claims['iss'] ?? $this->clients[$application]->id)
            ->relatedTo($claims['sub'] ?? (string) $this->actor->id)
            ->permittedFor($claims['aud'] ?? self::ISSUER.'/api/application-invitations')
            ->issuedAt(new DateTimeImmutable('@'.$iat))
            ->expiresAt(new DateTimeImmutable('@'.($claims['exp'] ?? $iat + 60)))
            ->identifiedBy(bin2hex(random_bytes(32)))
            ->withClaim('method', 'POST')
            ->withClaim('body_sha256', hash('sha256', $claims['body'] ?? '{}'));
        foreach ($claims['extra'] ?? [] as $name => $value) {
            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken(new Sha256, InMemory::plainText($claims['key'] ?? $this->privateKeys[$application]))->toString();
    }

    private function token(string $application): string
    {
        return $this->tokens[$application] ??= $this->issueToken($application);
    }

    private function issueToken(string $application, string $scope = ApplicationInvitations::SCOPE): string
    {
        $response = $this->post('/oauth/token', array_filter(['grant_type' => 'client_credentials', 'client_id' => $this->clients[$application]->id,
            'client_secret' => "{$application}-secret", 'scope' => $scope], fn ($value): bool => $value !== ''))->assertOk();

        return (string) $response->json('access_token');
    }

    private function pagesInvitation(string $email, ?string $token = null): AccessInvitation
    {
        $normalized = AccessInvitation::normalizeEmail($email);

        return AccessInvitation::query()->create([
            'application' => 'example-app', 'email' => $email, 'email_normalized' => $normalized,
            'token_hash' => AccessInvitation::hashToken($token ?? Str::random(43)), 'pending_key' => AccessInvitation::pendingKey('example-app', $normalized),
            'inviter_id' => $this->actor->id, 'inviter_credential_version' => (int) $this->actor->credential_version,
            'access' => ['application_admin' => true, 'workspaces' => []], 'expires_at' => now()->addDays(7),
        ]);
    }

    /** Accept as someone new, with the code emailed to the address (or a wrong one if none could be sent). */
    private function acceptAsNewPerson(string $link): TestResponse
    {
        $path = $this->path($link);

        return $this->post($path.'/accept', $this->newPerson($this->requestCode($path) ?? '000000'));
    }

    /** @return array<string, string> */
    private function newPerson(?string $code = null): array
    {
        return ['name' => 'Example Person', 'password' => 'a-new-password-example', 'password_confirmation' => 'a-new-password-example',
            ...($code === null ? [] : ['code' => $code])];
    }

    /** Ask for a code on this link's page; the code emailed, or null when none was sent. */
    private function requestCode(string $path): ?string
    {
        $before = Mail::sent(InvitationCodeMail::class)->count();
        $this->post($path.'/code');
        $sent = Mail::sent(InvitationCodeMail::class);

        return $sent->count() > $before ? $sent->last()->code : null;
    }

    private function path(string $link): string
    {
        return (string) parse_url($link, PHP_URL_PATH);
    }

    private function grant(User $user, string $application): void
    {
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $this->clients[$application]->id, 'subject' => $user->id,
            'created_at' => now(), 'updated_at' => now()]);
    }

    /** @return array{0: string, 1: string} private and public PEM */
    private function keyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $private);

        return [$private, openssl_pkey_get_details($key)['key']];
    }
}
