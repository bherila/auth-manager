<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class ApplicationIdentityRegistrationTest extends TestCase
{
    use RefreshDatabase;

    private const ENDPOINT = '/api/application-identities';

    private PassportClient $client;

    private string $secret;

    private array $payload;

    protected function setUp(): void
    {
        parent::setUp();
        $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Synthetic Application', ['https://app.example.test/auth/callback']);
        $this->secret = $this->client->plainSecret;
        RegisteredApplication::create(['key' => 'synthetic-app', 'name' => 'Synthetic Application', 'launch_url' => 'https://app.example.test', 'enabled' => true])
            ->clients()->attach($this->client->id);
        config(['auth-manager.application_registration.applications' => ['synthetic-app']]);
        $this->payload = ['external_id' => (string) Str::uuid(), 'name' => 'Synthetic Person', 'email' => 'person@example.test',
            'password_hash' => password_hash('synthetic-password', PASSWORD_BCRYPT, ['cost' => 10])];
        $this->withBasicAuth((string) $this->client->id, $this->secret);
    }

    public function test_registration_preserves_the_password_and_grants_only_its_own_client_without_roles_or_email_proof(): void
    {
        $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other Application', ['https://other.example.test/callback']);
        $response = $this->postJson(self::ENDPOINT, $this->payload)->assertCreated()->assertJsonPath('contract_version', 1)
            ->assertJsonPath('initial_credential_version', 0)->assertHeader('Cache-Control', 'no-store, private');
        $person = User::query()->where('email', $this->payload['email'])->sole();
        $this->assertSame($person->providerSubject(), $response->json('subject'));
        $this->assertSame($this->payload['password_hash'], $person->password);
        $this->assertTrue(Hash::check('synthetic-password', $person->password));
        $this->assertSame('user', $person->user_role);
        $this->assertNull($person->email_verified_at);
        $grants = app(OAuthClientGrantService::class);
        $this->assertTrue($grants->allows((string) $person->id, (string) $this->client->id));
        $this->assertFalse($grants->allows((string) $person->id, (string) $other->id));
        $this->assertStringNotContainsString($person->password, $response->getContent());
        $this->assertStringNotContainsString($person->password, DB::table('application_identity_registrations')->sole()->request_digest);
    }

    public function test_an_identical_retry_has_one_identity_and_one_receipt(): void
    {
        $first = $this->postJson(self::ENDPOINT, $this->payload)->assertCreated();
        $this->postJson(self::ENDPOINT, $this->payload)->assertOk()->assertExactJson($first->json());
        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('application_identity_registrations', 1);
        $this->postJson(self::ENDPOINT, [...$this->payload, 'name' => 'Different Person'])->assertConflict();
        $this->assertSame('Synthetic Person', User::query()->sole()->name);
    }

    public function test_matching_email_never_adopts_or_overwrites_an_existing_account(): void
    {
        $existing = User::factory()->create(['email' => 'PERSON@example.test']);
        $before = $existing->fresh()->getAttributes();
        $this->postJson(self::ENDPOINT, $this->payload)->assertConflict();
        $this->assertEquals($before, $existing->fresh()->getAttributes());
        $this->assertDatabaseCount('application_identity_registrations', 0);
        $this->assertFalse(app(OAuthClientGrantService::class)->allows((string) $existing->id, (string) $this->client->id));
    }

    public function test_registration_is_off_until_the_operator_lists_the_application(): void
    {
        config(['auth-manager.application_registration.applications' => []]);
        $this->postJson(self::ENDPOINT, $this->payload)->assertForbidden();
        $this->assertDatabaseCount('users', 0);
    }

    public function test_an_unmapped_or_dynamic_client_cannot_create_people(): void
    {
        $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.example.test/callback']);
        $this->withBasicAuth((string) $other->id, $other->plainSecret)->postJson(self::ENDPOINT, $this->payload)->assertForbidden();
        $this->client->forceFill(['dynamically_registered_at' => now()])->save();
        $this->withBasicAuth((string) $this->client->id, $this->secret)->postJson(self::ENDPOINT, $this->payload)->assertForbidden();
        $this->assertDatabaseCount('users', 0);
    }

    public function test_disabled_registry_and_invalid_credentials_are_refused(): void
    {
        RegisteredApplication::query()->update(['enabled' => false]);
        $this->postJson(self::ENDPOINT, $this->payload)->assertForbidden();
        $this->withBasicAuth((string) $this->client->id, 'wrong-secret')->postJson(self::ENDPOINT, $this->payload)->assertUnauthorized();
        $this->assertDatabaseCount('users', 0);
    }

    public function test_a_receipt_cannot_revive_a_deleted_identity_or_a_revoked_grant(): void
    {
        $this->postJson(self::ENDPOINT, $this->payload)->assertCreated();
        $person = User::query()->sole();
        app(OAuthClientGrantService::class)->revoke((string) $person->id, (string) $this->client->id);
        $this->postJson(self::ENDPOINT, $this->payload)->assertConflict();
        $this->assertFalse(app(OAuthClientGrantService::class)->allows((string) $person->id, (string) $this->client->id));
        $person->delete();
        $this->postJson(self::ENDPOINT, $this->payload)->assertConflict();
        $this->assertDatabaseCount('users', 1);
        $this->assertDatabaseCount('application_identity_registrations', 1);
    }

    public function test_extra_authority_and_unsafe_hashes_are_rejected_before_writes(): void
    {
        foreach ([['user_role' => 'admin'], ['email_verified' => true], ['subject' => 'chosen-subject'], ['client_id' => 'other-client'],
            ['password_hash' => 'plaintext'], ['password_hash' => password_hash('synthetic-password', PASSWORD_BCRYPT, ['cost' => 4])]] as $changes) {
            $this->postJson(self::ENDPOINT, [...$this->payload, ...$changes])->assertUnprocessable();
        }
        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('application_identity_registrations', 0);
    }

    public function test_only_operator_configuration_can_add_grants_and_a_retry_never_restores_them(): void
    {
        $extra = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Companion', ['https://companion.example.test/callback']);
        config(['auth-manager.application_registration.additional_client_grants' => ['synthetic-app' => [(string) $extra->id]]]);
        $this->postJson(self::ENDPOINT, $this->payload)->assertCreated();
        $person = User::query()->sole();
        $grants = app(OAuthClientGrantService::class);
        $this->assertTrue($grants->allows((string) $person->id, (string) $extra->id));
        $grants->revoke((string) $person->id, (string) $extra->id);
        $this->postJson(self::ENDPOINT, $this->payload)->assertOk();
        $this->assertFalse($grants->allows((string) $person->id, (string) $extra->id));
    }

    public function test_invalid_configured_grants_refuse_the_entire_registration(): void
    {
        config(['auth-manager.application_registration.additional_client_grants' => ['synthetic-app' => ['missing-client']]]);
        $this->postJson(self::ENDPOINT, $this->payload)->assertStatus(503);
        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('application_identity_registrations', 0);
    }

    public function test_creation_quotas_do_not_starve_identity_status_or_another_client(): void
    {
        for ($i = 0; $i < 30; $i++) {
            RateLimiter::hit('application-registration:client:'.$this->client->id, 60);
        }
        $this->postJson(self::ENDPOINT, $this->payload)->assertTooManyRequests()->assertHeader('Retry-After');
        $this->postJson('/api/reconciliation/identity-status', ['subject' => 'unknown-subject'])->assertOk();
        $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.example.test/callback']);
        RegisteredApplication::query()->sole()->clients()->attach($other->id);
        $this->withBasicAuth((string) $other->id, $other->plainSecret)->postJson(self::ENDPOINT, $this->payload)->assertCreated();
    }

    public function test_another_client_cannot_replay_or_claim_a_registration(): void
    {
        $this->postJson(self::ENDPOINT, $this->payload)->assertCreated();
        $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.example.test/callback']);
        RegisteredApplication::query()->sole()->clients()->attach($other->id);
        $this->withBasicAuth((string) $other->id, $other->plainSecret)->postJson(self::ENDPOINT, $this->payload)->assertConflict();
        $this->assertFalse(app(OAuthClientGrantService::class)->allows((string) User::query()->sole()->id, (string) $other->id));
    }
}
