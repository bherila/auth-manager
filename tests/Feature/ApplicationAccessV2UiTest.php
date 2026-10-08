<?php

namespace Tests\Feature;

use App\Http\Controllers\ApplicationAccessController;
use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Support\DelegatedAccessKeys;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Support\ViewErrorBag;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * The application-access page for an application on delegated access contract version 2 (#56).
 *
 * Version 2 applications advertise their own workspace roles, say per membership whether it can be
 * edited here, and may accept provisioning of a grant holder they have not seen. Version 1
 * applications keep `ApplicationAccessUiTest`, unchanged.
 */
class ApplicationAccessV2UiTest extends TestCase
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

    private User $actor;

    private PassportClient $client;

    private bool $provisioned = true;

    private bool $provisionAllowed = true;

    private bool $provisioning = true;

    private ?string $workspaceCursor = null;

    private bool $refuseUpdates = false;

    private array $memberships = [
        ['id' => 'workspace-a', 'role' => 'owner', 'editable' => false],
        ['id' => 'workspace-b', 'role' => 'sender', 'editable' => true],
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-access-v2-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['application-registry.launch_enabled' => true, 'delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'writes_applications' => ['example-app'], 'issuer' => 'https://identity.example.test',
            'key_id' => null, 'private_key_path' => null, 'keys_environment' => 'example-app|example-v1|'.$this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 2]],
        ]]);
        $this->actor = User::factory()->create(['name' => 'Example Actor', 'user_role' => 'user,access-manage:example-app,access-directory:example-app', 'password' => Hash::make('current-password-example')]);
        $this->client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Client',
            'secret' => 'example-secret', 'grant_types' => ['authorization_code'],
            'redirect_uris' => ['https://app.example.test/callback'], 'revoked' => false]);
        $application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application',
            'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $application->clients()->attach($this->client->id);
        $this->grant($this->actor);
        Http::preventStrayRequests();
        $this->fakeApplication();
        $this->actingAs($this->actor)->withSession([EnsureCredentialVersion::SESSION_KEY => 0]);
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_roles_come_from_the_application_and_a_non_editable_membership_is_read_only(): void
    {
        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertSee('Workspace A')
            ->assertSee('Owner (not editable here)')
            ->assertSee('<input type="hidden" name="workspaces[0][role]" value="owner">', false)
            ->assertSee('name="workspaces[1][role]"', false)
            ->assertSee('<option value="auditor">Auditor</option>', false)
            ->assertDontSee('Read and write');

        Http::assertSent(fn ($request) => $request['contract_version'] === 2);
    }

    public function test_an_update_names_roles_and_echoes_the_non_editable_membership(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor']],
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['contract_version'] === 2
            && $request['access'] === ['application_admin' => false, 'workspaces' => [
                ['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor'],
            ]]);
    }

    public function test_an_empty_role_removes_a_membership_and_a_new_one_names_its_role(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => '']],
            'new_workspace' => 'workspace-c', 'new_role' => 'admin',
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['access']['workspaces'] === [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-c', 'role' => 'admin']]);
    }

    public function test_a_role_the_application_does_not_offer_is_refused_before_anything_is_sent(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-b', 'role' => 'emperor']],
        ])->assertRedirect()->assertSessionHasErrors('workspaces');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_the_directory_lists_only_people_who_can_sign_in_to_the_application(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'email' => 'holder@example.test', 'user_role' => 'user']);
        $this->grant($holder);
        $disabled = User::factory()->create(['name' => 'Example Disabled', 'user_role' => 'user', 'disabled_at' => now()]);
        $this->grant($disabled);
        User::factory()->create(['name' => 'Example Stranger', 'user_role' => 'user']);

        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('Give access to someone new')
            ->assertSee('Example Holder (holder@example.test)')
            ->assertDontSee('Example Stranger')
            ->assertDontSee('Example Disabled');

        $this->browse(['directory_search' => 'Holder'])->assertOk()
            ->assertSee('Example Holder')
            ->assertDontSee('Example Actor (');
    }

    /**
     * An editable membership whose role the application no longer advertises stays as it is (#57 review).
     *
     * A select without that option would have the browser pick the first advertised role, so saving
     * any other change would silently change this membership too.
     */
    public function test_a_current_role_no_longer_advertised_is_read_only_and_echoed(): void
    {
        $this->memberships = [['id' => 'workspace-b', 'role' => 'retired-role', 'editable' => true]];

        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertSee('retired-role (not editable here)')
            ->assertSee('<input type="hidden" name="workspaces[0][role]" value="retired-role">', false)
            ->assertDontSee('<select name="workspaces[0][role]"', false);
    }

    /** A retired role posted back unchanged does not block saving another membership (#57 review). */
    public function test_an_unchanged_retired_role_does_not_block_saving_another_membership(): void
    {
        $this->memberships = [
            ['id' => 'workspace-a', 'role' => 'sender', 'editable' => true],
            ['id' => 'workspace-b', 'role' => 'retired-role', 'editable' => true],
        ];

        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'auditor'], ['id' => 'workspace-b', 'role' => 'retired-role']],
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['access']['workspaces'] === [['id' => 'workspace-a', 'role' => 'auditor'], ['id' => 'workspace-b', 'role' => 'retired-role']]);

        // Changing a membership to the retired role is still refused.
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'retired-role'], ['id' => 'workspace-b', 'role' => 'retired-role']],
        ])->assertRedirect()->assertSessionHasErrors('workspaces');
    }

    /** A subject is provisioned only in the exact form this provider issues it (#57 review). */
    public function test_provisioning_refuses_a_noncanonical_subject(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = false;

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => '00'.$holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHasErrors('subject');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    /** Workspaces past the first page can be reached while provisioning (#57 review). */
    public function test_provisioning_can_page_through_workspaces(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = false;
        $this->workspaceCursor = 'next-workspaces';

        $this->browse(['subject' => (string) $holder->id])->assertOk()
            ->assertSee('Create account and give access')
            ->assertSee('<input type="hidden" name="workspace_cursor" value="next-workspaces">', false)
            ->assertSee('More workspaces');
    }

    /**
     * Wildcard characters in a search are literal on every database (#57 review).
     *
     * SQLite gives backslash no meaning in LIKE, so a backslash-escaped `_` matched nothing and an
     * unescaped one matched any character.
     */
    public function test_a_search_treats_wildcard_characters_literally(): void
    {
        $underscored = User::factory()->create(['name' => 'Example Underscore', 'email' => 'first_last@example.test', 'user_role' => 'user']);
        $this->grant($underscored);
        $lookalike = User::factory()->create(['name' => 'Example Lookalike', 'email' => 'firstXlast@example.test', 'user_role' => 'user']);
        $this->grant($lookalike);

        $this->browse(['directory_search' => 'first_last'])->assertOk()
            ->assertSee('Example Underscore')
            ->assertDontSee('Example Lookalike');

        $this->browse(['directory_search' => '100%'])->assertOk()
            ->assertDontSee('Example Underscore')
            ->assertSee('No one who can sign in to this application matches.');
    }

    /**
     * Second-review B1: the directory lists grant holders across every workspace, so a manager
     * without the separate directory permission never sees it, not even with writes off. They
     * name a person by exact email instead.
     */
    public function test_a_manager_without_directory_access_sees_no_one_else_and_provisions_by_exact_email(): void
    {
        $this->actor->update(['user_role' => 'user,access-manage:example-app']);
        $other = User::factory()->create(['name' => 'Other Workspace Person', 'email' => 'other@example.test', 'user_role' => 'user']);
        $this->grant($other);

        config(['delegated-access.writes_enabled' => false]);
        $this->get('/applications/example-app/access')->assertOk()
            ->assertDontSee('Other Workspace Person')->assertDontSee('other@example.test');
        config(['delegated-access.writes_enabled' => true]);
        $this->get('/applications/example-app/access')->assertOk()
            ->assertDontSee('Other Workspace Person')->assertDontSee('other@example.test')
            ->assertSee('name="email"', false);

        $this->provisioned = false;
        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $other->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertSessionHasErrors(['subject', 'email']);

        $this->post('/applications/example-app/access/provision', [
            'email' => 'OTHER@example.test', 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_notice');
        Http::assertSent(fn ($request) => $request['operation'] === 'update' && $request['subject'] === (string) $other->id);
    }

    /** The exact-email answer is the same whether or not the person exists or can be provisioned. */
    public function test_exact_email_provisioning_reveals_nothing_about_who_exists(): void
    {
        $this->actor->update(['user_role' => 'user,access-manage:example-app']);
        $this->provisioned = false;
        $this->confirm();

        $unknown = $this->post('/applications/example-app/access/provision', [
            'email' => 'nobody@example.test', 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ]);
        $stranger = User::factory()->create(['email' => 'stranger@example.test', 'user_role' => 'user']);
        $ungranted = $this->post('/applications/example-app/access/provision', [
            'email' => 'stranger@example.test', 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ]);

        foreach ([$unknown, $ungranted] as $response) {
            $response->assertRedirect('/applications/example-app/access')
                ->assertSessionHas('access_notice', ApplicationAccessController::EMAIL_PROVISION_NOTICE)
                ->assertSessionHasNoErrors();
        }
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        $this->assertNotNull($stranger->id);
    }

    /**
     * Past the lookup, a real person who could be provisioned meets refusals a missing one never
     * reaches. Each must still answer exactly as for somebody who does not exist.
     */
    public function test_exact_email_refusals_answer_as_for_somebody_who_does_not_exist(): void
    {
        $this->actor->update(['user_role' => 'user,access-manage:example-app']);
        $this->provisioned = false;
        $holder = User::factory()->create(['email' => 'holder@example.test', 'user_role' => 'user']);
        $this->grant($holder);
        $answer = function (string $email, string $role = 'sender'): array {
            $response = $this->post('/applications/example-app/access/provision', [
                'email' => $email, 'new_workspace' => 'workspace-a', 'new_role' => $role,
            ]);
            $answer = [$response->headers->get('Location'), session('access_notice'), session('access_failure'), $this->errorKeys()];
            session()->forget(['access_notice', 'access_failure', 'errors']);

            return $answer;
        };
        $same = function (string $case, ?string $role = null) use ($answer): void {
            $this->assertSame($answer('nobody@example.test', $role ?? 'sender'), $answer('holder@example.test', $role ?? 'sender'), $case);
        };

        $same('without a recent confirmation');
        $this->confirm();
        $same('naming a role the application does not offer', 'not-a-role');
        $this->refuseUpdates = true;
        $same('when the application refuses the write');
        $this->refuseUpdates = false;
        config(['delegated-access.writes_applications' => []]);
        $same('with writes off for the application');
        config(['delegated-access.writes_applications' => ['example-app']]);
        $this->actor->update(['user_role' => 'user,access-view:example-app']);
        $same('with view permission only');

        $this->assertCount(1, Http::recorded(fn ($request) => $request['operation'] === 'update'), 'Only the refused write was sent');
    }

    public function test_without_a_delegated_permission_the_application_is_neither_listed_nor_reachable(): void
    {
        $this->actor->update(['user_role' => 'user']);

        $this->get('/applications/manage')->assertOk()->assertDontSee('Example Application');
        $this->get('/applications/example-app/access')->assertForbidden();
        Http::assertNothingSent();
    }

    public function test_view_permission_reads_but_cannot_write(): void
    {
        $this->actor->update(['user_role' => 'user,access-view:example-app']);

        $this->browse(['subject' => 'subject-example'])->assertOk()->assertSee('Workspace A')->assertDontSee('Save access');
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']],
        ])->assertRedirect()->assertSessionHas('access_failure', 'The application has not authorized this account to manage the requested access.');
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    /** Second-review M3: writes switched on globally do not reach an application not listed for writes. */
    public function test_writes_need_the_application_listed_for_writes(): void
    {
        config(['delegated-access.writes_applications' => ['another-app']]);

        $this->browse(['subject' => 'subject-example'])->assertOk()->assertDontSee('Save access');
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']],
        ])->assertRedirect()->assertSessionHas('access_failure', 'The application has not authorized this account to manage the requested access.');
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    /** Second-review M3: a write needs the application's own key; the shared key still serves reads. */
    public function test_writes_need_the_applications_own_signing_key(): void
    {
        config(['delegated-access.key_id' => 'example-v1', 'delegated-access.private_key_path' => $this->keyPath, 'delegated-access.keys_environment' => null]);

        $this->browse(['subject' => 'subject-example'])->assertOk()->assertSee('Workspace A')->assertDontSee('Save access');
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']],
        ])->assertRedirect()->assertSessionHas('access_failure', 'The application has not authorized this account to manage the requested access.');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        Http::assertSent(fn ($request) => $this->keyId($request) === 'example-v1');
    }

    /** A malformed key list is a configuration problem, reported once, not a refusal of the actor. */
    public function test_a_malformed_key_list_refuses_writes_as_unavailable_and_reports_once(): void
    {
        $this->provisioned = false;
        $this->confirm();
        $sent = count(Http::recorded());
        config(['delegated-access.keys_environment' => 'example-app|example-v1']);
        $reports = 0;
        $this->app->make(ExceptionHandler::class)->reportable(function (\InvalidArgumentException $failure) use (&$reports): bool {
            $reports += str_contains($failure->getMessage(), DelegatedAccessKeys::ENVIRONMENT) ? 1 : 0;

            return false;
        });

        // Provisioning checks write permission before anything else is sent.
        $this->post('/applications/example-app/access/provision', [
            'subject' => 'subject-example', 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_failure', 'Application access is unavailable. Try again later; saved results are not being shown as current.');
        $this->assertCount($sent, Http::recorded(), 'Nothing is sent');
        $this->assertSame(1, $reports, 'Reported once for the request');

        $reports = 0;
        $this->app->forgetScopedInstances();
        $this->get('/applications/example-app/access');
        $this->assertSame(1, $reports, 'A page that checks writes and reads repeatedly reports once');
    }

    public function test_assertions_name_the_applications_own_key(): void
    {
        config(['delegated-access.key_id' => 'shared-v1', 'delegated-access.keys_environment' => 'example-app|example-own-v2|'.$this->keyPath]);

        $this->browse(['subject' => 'subject-example'])->assertOk()->assertSee('Save access');

        $this->assertNotEmpty(Http::recorded());
        foreach (Http::recorded() as [$request]) {
            $this->assertSame('example-own-v2', $this->keyId($request));
        }
    }

    /** Second-review M6: a new membership's role is chosen, never defaulted to the first (most senior) role. */
    public function test_a_new_membership_role_must_be_chosen(): void
    {
        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertSeeInOrder(['name="new_role"', '<option value="">Choose a role</option>', '<option value="owner">'], false);

        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']],
            'new_workspace' => 'workspace-c', 'new_role' => '',
        ])->assertSessionHasErrors('new_role');
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_the_directory_is_absent_when_the_application_does_not_offer_provisioning(): void
    {
        $this->provisioning = false;

        $this->get('/applications/example-app/access')->assertOk()->assertDontSee('Give access to someone new');
    }

    public function test_provisioning_sends_a_null_revision_with_the_role_and_display_name(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = false;

        $this->browse(['subject' => (string) $holder->id])->assertOk()->assertSee('Create account and give access');

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['contract_version'] === 2
            && $request['subject'] === (string) $holder->id
            && array_key_exists('expected_revision', $request->data()) && $request['expected_revision'] === null
            && $request['display_name'] === 'Example Holder'
            && $request['access'] === ['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]]);
    }

    public function test_provisioning_refuses_someone_who_cannot_sign_in_to_the_application(): void
    {
        $stranger = User::factory()->create(['name' => 'Example Stranger', 'user_role' => 'user']);
        $this->provisioned = false;

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $stranger->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHasErrors('subject');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        // The application authorized the actor before anybody was looked up (#57 review).
        Http::assertSent(fn ($request) => $request['operation'] === 'capabilities');
    }

    public function test_provisioning_refuses_an_account_the_application_no_longer_offers_to_create(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = true;

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_failure');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_a_version_one_answer_from_a_version_two_application_is_refused(): void
    {
        Http::swap(new Factory);
        Http::fake(['*' => Http::response(['contract_version' => 1, 'application' => 'example-app', 'operation' => 'capabilities',
            'controls' => ['application_admin' => false, 'workspace_permissions' => ['read', 'write']]], 200)]);

        $request = Request::create('/synthetic-delegated-ui', 'POST');
        $request->setUserResolver(fn (): User => $this->actor);
        $request->setLaravelSession(app('session.store'));
        $request->session()->put(EnsureCredentialVersion::SESSION_KEY, 0);

        try {
            app(DelegatedAccessTransport::class)->send($request, 'example-app', ['operation' => 'capabilities']);
            $this->fail('A version 1 answer was accepted from an application configured for version 2.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame('invalid_response', $exception->outcome);
        }
    }

    private function fakeApplication(): void
    {
        Http::fake(function ($request) {
            $operation = $request['operation'];
            $data = match ($operation) {
                'capabilities' => ['controls' => ['application_admin' => false, 'workspace_roles' => [
                    ['id' => 'owner', 'label' => 'Owner'], ['id' => 'admin', 'label' => 'Administrator'],
                    ['id' => 'sender', 'label' => 'Sender'], ['id' => 'auditor', 'label' => 'Auditor'],
                ], 'provisioning' => $this->provisioning]],
                'subjects' => ['subjects' => [['subject' => 'subject-example', 'label' => 'Example Account']], 'next_cursor' => null],
                'workspaces' => ['workspaces' => [
                    ['id' => 'workspace-a', 'label' => 'Workspace A'], ['id' => 'workspace-b', 'label' => 'Workspace B'],
                    ['id' => 'workspace-c', 'label' => 'Workspace C'],
                ], 'next_cursor' => $this->workspaceCursor],
                'update' => ['subject' => $request['subject'], 'provisioned' => true, 'revision' => 'revision-after',
                    'access' => ['application_admin' => false, 'workspaces' => array_map(
                        fn (array $membership): array => [...$membership, 'editable' => true], $request['access']['workspaces'])],
                    'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false]],
                default => ['subject' => $request['subject'], 'provisioned' => $this->provisioned,
                    'revision' => $this->provisioned ? 'revision-example' : null,
                    'access' => $this->provisioned ? ['application_admin' => false, 'workspaces' => $this->memberships] : null,
                    'allowed_edits' => ['application_admin' => false, 'workspaces' => $this->provisioned,
                        'provision' => ! $this->provisioned && $this->provisionAllowed]],
            };

            if ($operation === 'update' && $this->refuseUpdates) {
                return Http::response(['error' => 'not_authorized'], 403);
            }

            return Http::response(['contract_version' => 2, 'application' => 'example-app', 'operation' => $operation, ...$data]);
        });
    }

    /** @return list<string>|null */
    private function errorKeys(): ?array
    {
        $errors = session('errors');

        return match (true) {
            $errors instanceof ViewErrorBag => $errors->getBag('default')->keys(),
            is_array($errors) => array_keys($errors),
            default => null,
        };
    }

    private function keyId(\Illuminate\Http\Client\Request $request): ?string
    {
        $assertion = substr($request->header('Authorization')[0] ?? '', strlen('Bearer '));
        $header = json_decode(base64_decode(strtr(explode('.', $assertion)[0], '-_', '+/')), true);

        return is_array($header) ? ($header['kid'] ?? null) : null;
    }

    private function grant(User $user): void
    {
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $this->client->id, 'subject' => $user->id,
            'created_at' => now(), 'updated_at' => now()]);
    }

    private function confirm(): void
    {
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example'])
            ->assertRedirect('/applications/example-app/access');
    }

    private function browse(array $input): TestResponse
    {
        $response = $this->post('/applications/example-app/access/browse', $input)->assertRedirect();

        return $this->get($response->headers->get('Location'));
    }
}
