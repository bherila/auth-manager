<?php

namespace Tests\Feature;

use App\Http\Controllers\ApplicationAccessController;
use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\Fixtures\FakesVersion3Application;
use Tests\TestCase;

/**
 * The application-access page for an application on delegated access contract version 3.
 *
 * Version 3 is version 2 plus search, removal, metadata and operation receipts. What version 2 does
 * (roles, editable memberships, provisioning) is `ApplicationAccessV2UiTest`'s, and stays there.
 */
class ApplicationAccessV3UiTest extends TestCase
{
    use DatabaseMigrations;
    use FakesVersion3Application;

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

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-access-v3-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['application-registry.launch_enabled' => true, 'delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'writes_applications' => ['example-app'], 'issuer' => 'https://identity.example.test',
            'key_id' => null, 'private_key_path' => null, 'keys_environment' => 'example-app|example-v1|'.$this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
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
        $this->fakeVersion3Application();
        $this->actingAs($this->actor)->withSession([EnsureCredentialVersion::SESSION_KEY => 0]);
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_the_page_speaks_version_3_and_the_update_form_carries_a_fresh_operation_id(): void
    {
        $first = $this->operationIdIn($this->browse(['subject' => 'subject-example'])->assertOk()->assertSee('Save access'));
        $second = $this->operationIdIn($this->get('/applications/example-app/access?subject=subject-example')->assertOk());

        $this->assertTrue(DelegatedContract::validOperationId($first));
        // Minted per rendering: each rendering of the form is a new user action.
        $this->assertNotSame($first, $second);
        $this->assertCount(0, Http::recorded(fn (ClientRequest $request) => $request['contract_version'] !== 3));
    }

    public function test_an_update_carries_the_posted_operation_id_and_a_resubmission_reuses_it(): void
    {
        $this->confirm();
        $operationId = $this->operationIdIn($this->get('/applications/example-app/access?subject=subject-example'));
        $form = [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor']],
            'operation_id' => $operationId,
        ];

        // A double submit of the same form is the same operation, answered from the receipt there.
        $this->post('/applications/example-app/access/update', $form)->assertRedirect()->assertSessionHas('access_updated', true);
        $this->post('/applications/example-app/access/update', $form)->assertRedirect()->assertSessionHas('access_updated', true);

        $updates = Http::recorded(fn (ClientRequest $request) => $request['operation'] === 'update');
        $this->assertCount(2, $updates);
        foreach ($updates as [$request]) {
            $this->assertSame(3, $request['contract_version']);
            $this->assertSame($operationId, $request['operation_id']);
            $this->assertSame(['application_admin' => false, 'workspaces' => [
                ['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor'],
            ]], $request['access']);
        }
        $audits = DB::table('auth_audit_log')->where('event', 'delegated_access_update_attempt')->pluck('metadata')->map(fn ($m) => json_decode($m, true));
        $this->assertSame([$operationId, $operationId], $audits->pluck('operation_id')->all());
        $this->assertNotSame($audits[0]['correlation'], $audits[1]['correlation']);
    }

    public function test_a_write_without_a_valid_operation_id_is_refused_before_anything_is_sent(): void
    {
        $this->confirm();
        foreach ([null, '', 'too-short', str_repeat('a', 65), str_repeat('a', 40).'!'] as $operationId) {
            $this->post('/applications/example-app/access/update', array_filter([
                'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
                'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']], 'operation_id' => $operationId,
            ], fn ($value) => $value !== null))->assertRedirect('/applications/example-app/access?subject=subject-example')
                ->assertSessionHasErrors('operation_id');
        }

        $this->assertCount(0, Http::recorded(fn (ClientRequest $request) => $request['operation'] === 'update'));
    }

    public function test_provisioning_carries_the_forms_operation_id(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->v3Provisioned = false;
        $page = $this->browse(['subject' => (string) $holder->id])->assertOk()->assertSee('Create account and give access');
        $operationId = $this->operationIdIn($page);

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender', 'operation_id' => $operationId,
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn (ClientRequest $request) => $request['operation'] === 'update' && $request['expected_revision'] === null
            && $request['operation_id'] === $operationId && $request['contract_version'] === 3);
    }

    public function test_after_an_uncertain_update_the_page_shows_what_the_receipt_says(): void
    {
        $this->confirm();
        $this->v3WriteFailure = 'server_error';
        $form = fn (): array => [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor']],
            'operation_id' => DelegatedContract::operationId(),
        ];
        $back = '/applications/example-app/access?subject=subject-example';

        // Applied after all.
        $this->v3Receipt = ['status' => 200, 'response' => ['operation' => 'update', ...$this->v3UpdatedState('subject-example', [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor']])]];
        $this->post('/applications/example-app/access/update', $form())->assertRedirect($back)->assertSessionHas('access_updated', true);
        // Refused, with the refusal it got.
        $this->v3Receipt = ['status' => 409, 'response' => ['error' => 'revision_conflict']];
        $this->post('/applications/example-app/access/update', $form())->assertRedirect($back)
            ->assertSessionHas('access_failure', 'Access changed since you opened this form. Reload current access before editing again.');
        // Still unknown.
        $this->v3Receipt = null;
        $this->post('/applications/example-app/access/update', $form())->assertRedirect($back)
            ->assertSessionHas('access_failure', fn (string $message): bool => str_contains($message, 'does not show an outcome yet'));
        $this->get($back)->assertOk()->assertSee('does not show an outcome yet');

        // Each write was sent once and looked up once; none was sent again.
        $this->assertSame(['update', 'receipt', 'update', 'receipt', 'update', 'receipt'],
            array_values(array_filter($this->v3Sent, fn (string $operation): bool => in_array($operation, ['update', 'receipt'], true))));
    }

    /**
     * Codex review on #77: an answer that does not fit the advertised capabilities is uncertain inside
     * the transport, so it is never audited as a success and its receipt is asked for, once.
     */
    public function test_an_answer_that_does_not_fit_the_capabilities_is_never_audited_as_success(): void
    {
        $this->v3Roles = [];
        $this->v3Memberships = [];
        $this->v3AnswerMemberships = [['id' => 'workspace-a', 'role' => 'owner']];
        // The receipt holds the same misfit answer: it settles nothing.
        $this->v3Receipt = ['status' => 200, 'response' => ['operation' => 'update', ...$this->v3UpdatedState('subject-example', $this->v3AnswerMemberships)]];
        $this->confirm();

        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'operation_id' => DelegatedContract::operationId(),
        ])->assertRedirect()->assertSessionMissing('access_updated')
            ->assertSessionHas('access_failure', fn (string $message): bool => str_contains($message, 'does not show an outcome yet'));

        $outcomes = DB::table('auth_audit_log')->whereIn('event', ['delegated_access_receipt_check', 'delegated_access_update_result'])->orderBy('id')
            ->pluck('metadata')->map(fn ($metadata) => json_decode($metadata, true)['outcome'])->all();
        $this->assertSame(['unknown', DelegatedAccessTransport::STILL_UNKNOWN], $outcomes);
        $this->assertSame(['update', 'receipt'], array_values(array_filter($this->v3Sent, fn (string $operation): bool => in_array($operation, ['update', 'receipt'], true))));
    }

    public function test_searching_people_sends_the_query_as_the_actor_and_keeps_paging_within_it(): void
    {
        $this->v3Subjects = [
            ['subject' => 'subject-1', 'label' => 'Example One'], ['subject' => 'subject-2', 'label' => 'Unrelated Person'],
            ['subject' => 'subject-3', 'label' => 'example two'], ['subject' => 'subject-4', 'label' => 'EXAMPLE three'],
        ];

        $page = $this->browse(['subject_query' => 'example'])->assertOk()
            ->assertSee('Example One')->assertSee('example two')->assertDontSee('Unrelated Person')->assertDontSee('EXAMPLE three')
            ->assertSee('<input type="hidden" name="subject_query" value="example">', false)
            ->assertSee('<input type="hidden" name="subject_cursor" value="q:example|2">', false);
        $this->assertSame('example', $this->lastSent('subjects')['query']);
        $this->assertSame((string) $this->actor->id, $this->claims($this->lastSentRequest('subjects'))['sub']);
        // The person's review link keeps the search, so the list stays as it was.
        $page->assertSee(e(route('applications.access', ['application' => 'example-app', 'subject' => 'subject-1', 'subject_query' => 'example'])), false);

        // The next page asks for the same search with its cursor.
        $this->browse(['subject_query' => 'example', 'subject_cursor' => 'q:example|2'])->assertOk()
            ->assertSee('EXAMPLE three')->assertDontSee('Example One');
        $this->assertSame(['cursor' => 'q:example|2', 'query' => 'example'], array_intersect_key($this->lastSent('subjects'), ['cursor' => 1, 'query' => 1]));

        $this->browse(['subject_query' => 'nobody'])->assertOk()->assertSee('No account you can see matches this search.');
    }

    public function test_searching_workspaces_narrows_the_workspace_choices_and_keeps_the_account(): void
    {
        $this->browse(['subject' => 'subject-example', 'workspace_query' => 'Workspace C'])->assertOk()
            ->assertSee('<option value="workspace-c">Workspace C</option>', false)
            ->assertDontSee('<option value="workspace-a">', false)
            ->assertSee('Workspace choices on this page list only workspaces matching this search.');
        $this->assertSame('Workspace C', $this->lastSent('workspaces')['query']);
        $this->assertSame('subject-example', $this->lastSent('read')['subject']);
        $this->assertArrayNotHasKey('query', $this->lastSent('subjects'));
    }

    /** Codex review on #77: a write returns to the page with the searches that were in force. */
    public function test_write_forms_carry_the_searches_in_force_and_return_to_them(): void
    {
        $page = $this->get('/applications/example-app/access?'.http_build_query(['subject' => 'subject-example', 'subject_query' => 'Example', 'workspace_query' => 'Workspace']))->assertOk();
        foreach (['update', 'remove'] as $route) {
            preg_match('/<form method="post" action="[^"]*\/access\/'.$route.'".*?<\/form>/s', $page->getContent(), $form);
            $this->assertStringContainsString('<input type="hidden" name="subject_query" value="Example">', $form[0], $route);
            $this->assertStringContainsString('<input type="hidden" name="workspace_query" value="Workspace">', $form[0], $route);
        }

        $this->confirm();
        $searches = ['subject_query' => 'Example', 'workspace_query' => 'Workspace'];
        $back = '/applications/example-app/access?'.http_build_query(['subject' => 'subject-example', ...$searches]);
        $update = ['subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']], 'operation_id' => DelegatedContract::operationId()];
        $this->post('/applications/example-app/access/update', [...$update, ...$searches])->assertRedirect($back)->assertSessionHas('access_updated', true);
        $this->post('/applications/example-app/access/remove', [...$this->removal(), ...$searches])->assertRedirect($back)->assertSessionHas('access_notice');
        // A refusal returns to the same filtered page.
        $this->v3WriteRefusal = [409, 'revision_conflict'];
        $this->post('/applications/example-app/access/update', [...$update, 'operation_id' => DelegatedContract::operationId(), ...$searches])
            ->assertRedirect($back)->assertSessionHas('access_failure');
        // A search the contract would refuse is dropped, never sent on or refused.
        $this->v3WriteRefusal = null;
        $this->post('/applications/example-app/access/update', [...$update, 'operation_id' => DelegatedContract::operationId(), 'subject_query' => 'x', 'workspace_query' => 'Workspace'])
            ->assertRedirect('/applications/example-app/access?'.http_build_query(['subject' => 'subject-example', 'workspace_query' => 'Workspace']))
            ->assertSessionHas('access_updated', true);
    }

    public function test_provisioning_forms_carry_the_searches_in_force_and_return_to_them(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->v3Provisioned = false;
        $page = $this->get('/applications/example-app/access?'.http_build_query(['subject' => (string) $holder->id, 'subject_query' => 'Example']))->assertOk();
        preg_match('/<form method="post" action="[^"]*\/access\/provision".*?<\/form>/s', $page->getContent(), $form);
        $this->assertStringContainsString('<input type="hidden" name="subject_query" value="Example">', $form[0]);

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
            'operation_id' => DelegatedContract::operationId(), 'subject_query' => 'Example',
        ])->assertRedirect('/applications/example-app/access?'.http_build_query(['subject' => (string) $holder->id, 'subject_query' => 'Example']));
    }

    public function test_a_search_the_contract_would_refuse_is_never_sent(): void
    {
        foreach (['x', str_repeat('y', 101)] as $query) {
            $this->post('/applications/example-app/access/browse', ['subject_query' => $query])->assertSessionHasErrors('subject_query');
            $this->post('/applications/example-app/access/browse', ['workspace_query' => $query])->assertSessionHasErrors('workspace_query');
            $this->get('/applications/example-app/access?'.http_build_query(['subject_query' => $query]))->assertSessionHasErrors('subject_query');
        }

        $this->assertCount(0, Http::recorded(fn (ClientRequest $request) => isset($request['query'])));
    }

    public function test_searching_needs_the_same_permission_as_listing(): void
    {
        $this->actor->update(['user_role' => 'user']);

        $this->get('/applications/example-app/access?subject_query=example')->assertForbidden();

        Http::assertNothingSent();
    }

    public function test_remove_is_offered_only_when_the_application_allows_it_and_writes_are_possible(): void
    {
        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertSee('Remove from this application')
            ->assertSee('The account and its history stay in Example Application.')
            ->assertSee('name="confirm_removal"', false);

        $this->v3RemoveAllowed = false;
        $this->get('/applications/example-app/access?subject=subject-example')->assertOk()->assertDontSee('Remove from this application');

        $this->v3RemoveAllowed = true;
        config(['delegated-access.writes_applications' => []]);
        $this->get('/applications/example-app/access?subject=subject-example')->assertOk()->assertDontSee('Remove from this application');
    }

    public function test_removing_sends_the_forms_operation_id_and_keeps_the_account(): void
    {
        $this->confirm();
        $page = $this->get('/applications/example-app/access?subject=subject-example');
        preg_match('/action="[^"]*\/remove".*?name="operation_id" value="([^"]+)"/s', $page->getContent(), $match);
        $operationId = $match[1];

        $this->post('/applications/example-app/access/remove', $this->removal($operationId))
            ->assertRedirect('/applications/example-app/access?subject=subject-example')
            ->assertSessionHas('access_notice', ApplicationAccessController::REMOVED_NOTICE);
        // A resubmission of the same form is the same removal.
        $this->post('/applications/example-app/access/remove', $this->removal($operationId))->assertSessionHas('access_notice');

        $removals = Http::recorded(fn (ClientRequest $request) => $request['operation'] === 'remove');
        $this->assertCount(2, $removals);
        foreach ($removals as [$request]) {
            $this->assertSame(['contract_version' => 3, 'application' => 'example-app', 'operation' => 'remove', 'subject' => 'subject-example',
                'expected_revision' => 'revision-example', 'operation_id' => $operationId], $request->data());
        }
        $this->assertSame(['remove', 'remove'], DB::table('auth_audit_log')->where('event', 'delegated_access_update_attempt')->pluck('metadata')
            ->map(fn ($metadata) => json_decode($metadata, true)['operation'])->all());
    }

    public function test_removing_needs_the_explicit_confirmation(): void
    {
        $this->confirm();
        foreach ([null, '0', 'no'] as $confirmation) {
            $this->from('/applications/example-app/access?subject=subject-example')
                ->post('/applications/example-app/access/remove', array_filter([...$this->removal(), 'confirm_removal' => $confirmation], fn ($value) => $value !== null))
                ->assertRedirect('/applications/example-app/access?subject=subject-example')
                ->assertSessionHasErrors('confirm_removal');
        }

        $this->assertNothingRemoved();
    }

    public function test_removing_needs_a_recent_confirmation_like_any_other_write(): void
    {
        $this->post('/applications/example-app/access/remove', $this->removal())
            ->assertRedirect('/applications/example-app/access?subject=subject-example')
            ->assertSessionHas('access_failure', 'Confirm your password or sign in again before changing application access.');

        $this->assertNothingRemoved();
        // Refused before anything about the account was read.
        $this->assertCount(0, Http::recorded(fn (ClientRequest $request) => $request['operation'] === 'read'));
    }

    public function test_removing_needs_manage_permission_and_writes_enabled(): void
    {
        $this->confirm();
        config(['delegated-access.writes_applications' => []]);
        $this->post('/applications/example-app/access/remove', $this->removal())->assertSessionHas('access_failure');
        config(['delegated-access.writes_applications' => ['example-app']]);
        $this->actor->update(['user_role' => 'user,access-view:example-app']);
        $this->post('/applications/example-app/access/remove', $this->removal())->assertSessionHas('access_failure');

        $this->assertNothingRemoved();
    }

    public function test_removal_is_not_sent_when_a_fresh_read_does_not_offer_it(): void
    {
        $this->confirm();
        $this->v3RemoveAllowed = false;

        $this->post('/applications/example-app/access/remove', $this->removal())
            ->assertSessionHas('access_failure', 'The application does not offer to remove this account\'s access now. Review its current access.');

        $this->assertNothingRemoved();
    }

    public function test_an_uncertain_removal_is_settled_by_its_receipt_and_never_resent(): void
    {
        $this->confirm();
        $this->v3WriteFailure = 'timeout';
        $this->v3Receipt = ['status' => 200, 'response' => ['operation' => 'remove', ...$this->v3UpdatedState('subject-example', [])]];

        $this->post('/applications/example-app/access/remove', $this->removal())
            ->assertSessionHas('access_notice', ApplicationAccessController::REMOVED_NOTICE);

        $this->assertSame(['remove', 'receipt'], array_values(array_filter($this->v3Sent, fn (string $operation): bool => in_array($operation, ['remove', 'receipt'], true))));
    }

    public function test_a_version_2_application_has_no_removal(): void
    {
        $this->confirm();
        config(['delegated-access.applications.example-app.contract_version' => 2]);

        $this->post('/applications/example-app/access/remove', $this->removal())->assertNotFound();

        $this->assertNothingRemoved();
    }

    public function test_the_account_list_shows_the_observations_the_application_reports(): void
    {
        $this->v3Subjects = [
            ['subject' => 'subject-1', 'label' => 'Example One', 'provisioned_at' => '2026-10-01T09:30:00Z', 'last_seen_at' => '2026-10-09T18:05:00+02:00'],
            ['subject' => 'subject-2', 'label' => 'Example Two', 'provisioned_at' => '2026-10-02T00:00:00Z', 'last_seen_at' => null],
        ];

        $this->get('/applications/example-app/access')->assertOk()
            ->assertSeeInOrder(['<th scope="col" class="p-2">Account</th>', '<th scope="col" class="p-2">Added</th>', '<th scope="col" class="p-2">Last seen</th>'], false)
            ->assertDontSee('First sign-in')
            ->assertSee('<time datetime="2026-10-01T09:30:00Z">2026-10-01 09:30 UTC</time>', false)
            ->assertSee('<time datetime="2026-10-09T18:05:00+02:00">2026-10-09 16:05 UTC</time>', false)
            ->assertSee('Not recorded');

        // No observations reported: no columns for them.
        $this->v3Subjects = [['subject' => 'subject-1', 'label' => 'Example One']];
        $this->get('/applications/example-app/access')->assertOk()->assertDontSee('Added')->assertDontSee('Last seen');
    }

    public function test_an_accounts_detail_shows_the_observations_the_application_reports(): void
    {
        $this->v3StateMetadata = ['provisioned_at' => '2026-10-01T09:30:00Z', 'first_sign_in_at' => null, 'last_seen_at' => '2026-10-09T16:05:00.250Z'];

        $this->get('/applications/example-app/access?subject=subject-example')->assertOk()
            ->assertSeeInOrder(['Added', '2026-10-01 09:30 UTC', 'First sign-in', 'Not recorded', 'Last seen', '2026-10-09 16:05 UTC'])
            ->assertSee('they do not affect access');

        $this->v3StateMetadata = [];
        $this->get('/applications/example-app/access?subject=subject-example')->assertOk()->assertDontSee('First sign-in')->assertDontSee('they do not affect access');
    }

    public function test_role_descriptions_are_shown_where_the_application_gives_them(): void
    {
        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('Roles in Example Application')
            ->assertSee('<dt class="font-semibold">Sender</dt><dd>Sends documents for signature.</dd>', false)
            ->assertDontSee('<dt class="font-semibold">Owner</dt>', false);

        $this->v3Roles = [['id' => 'owner', 'label' => 'Owner']];
        $this->get('/applications/example-app/access')->assertOk()->assertDontSee('Roles in Example Application');
    }

    /** @return array<string, string> */
    private function removal(?string $operationId = null): array
    {
        return ['subject' => 'subject-example', 'expected_revision' => 'revision-example', 'confirm_removal' => '1',
            'operation_id' => $operationId ?? DelegatedContract::operationId()];
    }

    private function assertNothingRemoved(): void
    {
        $this->assertNotContains('remove', $this->v3Sent);
    }

    private function operationIdIn(TestResponse $response): string
    {
        preg_match('/name="operation_id" value="([^"]+)"/', $response->getContent(), $match);
        $this->assertNotEmpty($match, 'The form carries no operation id.');

        return $match[1];
    }

    /** @return array<string, mixed> the last request of this operation the application was sent */
    private function lastSent(string $operation): array
    {
        return $this->lastSentRequest($operation)->data();
    }

    private function lastSentRequest(string $operation): ClientRequest
    {
        return Http::recorded(fn (ClientRequest $request) => $request['operation'] === $operation)->last()[0];
    }

    /** @return array<string, mixed> */
    private function claims(ClientRequest $request): array
    {
        $payload = explode('.', substr($request->header('Authorization')[0], strlen('Bearer ')))[1];

        return json_decode(base64_decode(strtr($payload, '-_', '+/')), true, flags: JSON_THROW_ON_ERROR);
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
