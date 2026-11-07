<?php

namespace Tests\Feature;

use BWH\Auth\OAuth\OAuthIdentity;
use BWH\Auth\OAuth\Session\ProviderSession;
use BWH\Auth\OAuth\Session\ProviderSessionExpired;
use BWH\Auth\OAuth\Session\ProviderStatusUnavailable;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\ClientRepository;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/** In-process provider/shared-client contract acceptance, not a deployed consumer. */
class AccountManagementAcceptanceTest extends TestCase
{
    use RefreshDatabase;

    private bool $unavailable = false;

    protected function setUp(): void
    {
        parent::setUp();
        $this->freezeTime();
    }

    private function consumer(User $user): Request
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Consumer', ['https://app.example.test/callback']);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        config(['bherila-auth.oauth_client' => [
            'provider' => 'example-provider', 'base_url' => 'https://identity.example.test',
            'client_id' => (string) $client->id, 'client_secret' => $client->plainSecret,
        ]]);
        Http::preventStrayRequests();
        Http::fake(['https://identity.example.test/api/reconciliation/identity-status' => function (ClientRequest $request) {
            if ($this->unavailable) {
                return Http::response(['message' => 'Unavailable'], 503);
            }
            // Forward the shared client's real subject and Basic credential to
            // the provider kernel; do not fabricate an active status response.
            $response = $this->withHeader('Authorization', $request->header('Authorization')[0] ?? '')
                ->postJson('/api/reconciliation/identity-status', $request->data());

            return Http::response($response->json(), $response->status());
        }]);
        $request = Request::create('https://app.example.test/private');
        $store = new Store('synthetic-consumer', new ArraySessionHandler(120));
        $store->start();
        $request->setLaravelSession($store);
        app(ProviderSession::class)->remember($request, new OAuthIdentity('example-provider', (string) $user->id,
            $user->name, $user->email, credentialVersion: (int) $user->credential_version));

        return $request;
    }

    public function test_real_password_rotation_ends_the_immutable_consumer_baseline_at_the_freshness_bound(): void
    {
        $user = User::factory()->create(['user_role' => 'user', 'password' => 'current-example-password']);
        $request = $this->consumer($user);
        $session = app(ProviderSession::class);
        $this->actingAs($user)->putJson('/settings/password', [
            'current_password' => 'current-example-password', 'password' => 'next-example-password',
            'password_confirmation' => 'next-example-password',
        ])->assertOk();
        $this->assertSame(1, $user->fresh()->credential_version);
        $this->travel(299)->seconds();
        $this->assertSame(0, $session->assertActive($request, 'example-provider', (string) $user->id)->credentialVersion);
        Http::assertNothingSent();
        $this->travel(1)->seconds();
        try {
            $session->assertActive($request, 'example-provider', (string) $user->id);
            $this->fail('An existing consumer session must not adopt the replacement credential generation.');
        } catch (ProviderSessionExpired) {
            $this->assertFalse($request->session()->has('bherila_auth.provider_session'));
        }
        Http::assertSentCount(1);
    }

    public static function inactiveMutations(): array
    {
        return [['disable'], ['delete']];
    }

    #[DataProvider('inactiveMutations')]
    public function test_privileged_consumer_work_observes_real_disable_or_delete_without_waiting(string $mutation): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $user = User::factory()->create(['user_role' => 'user']);
        $request = $this->consumer($user);
        if ($mutation === 'disable') {
            $this->actingAs($admin)->postJson('/api/admin/users/'.$user->id.'/disable')->assertOk();
        } else {
            $this->actingAs($admin)->deleteJson('/api/admin/users/'.$user->id)->assertAccepted();
        }
        try {
            app(ProviderSession::class)->assertActive($request, 'example-provider', (string) $user->id, fresh: true);
            $this->fail('Privileged consumer work must observe current account inactivity immediately.');
        } catch (ProviderSessionExpired) {
            $this->assertFalse($request->session()->has('bherila_auth.provider_session'));
        }
        Http::assertSentCount(1);
    }

    public function test_outage_refuses_privileged_and_stale_work_without_extending_or_erasing_the_session(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $request = $this->consumer($user);
        $session = app(ProviderSession::class);
        $baseline = $request->session()->all();
        $this->unavailable = true;
        $this->travel(299)->seconds();
        $session->assertActive($request, 'example-provider', (string) $user->id);
        Http::assertNothingSent();
        foreach ([true, false] as $privileged) {
            if (! $privileged) {
                $this->travel(1)->seconds();
            }
            try {
                $session->assertActive($request, 'example-provider', (string) $user->id, fresh: $privileged);
                $this->fail('Unavailable current status must not authorize this request.');
            } catch (ProviderStatusUnavailable) {
                $this->assertSame($baseline, $request->session()->all());
            }
        }
        $this->unavailable = false;
        $this->assertSame(0, $session->assertActive($request, 'example-provider', (string) $user->id)->credentialVersion);
        $this->assertSame($baseline['bherila_auth']['provider_session']['generation'], $request->session()->get('bherila_auth.provider_session.generation'));
        Http::assertSentCount(3);
    }

    public function test_real_retention_purge_and_late_acknowledgement_remain_distinct_in_operator_progress(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        $clients = [];
        foreach (['Available Example', 'Unavailable Example'] as $name) {
            $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient($name, ['https://app.example.test/callback']);
            $clients[] = [$client, $client->plainSecret];
        }
        $id = $this->actingAs($admin)->deleteJson('/api/admin/users/'.$target->id)
            ->assertAccepted()->json('tombstone.id');
        [$available, $availableSecret] = $clients[0];
        [$unavailable, $unavailableSecret] = $clients[1];
        $this->withBasicAuth((string) $available->id, $availableSecret)
            ->putJson('/api/reconciliation/identity-tombstones/'.$id.'/acknowledgement')->assertOk();
        $this->actingAs($admin)->getJson('/api/admin/identity-lifecycle')->assertOk()
            ->assertJsonPath('data.0.pending_count', 1)->assertJsonPath('data.0.provider_purged_at', null)
            ->assertJsonPath('data.0.retention_expired', false);
        $this->artisan('identities:purge-tombstones')->assertSuccessful();
        $this->assertNotNull(User::withTrashed()->find($target->id));
        $this->travel(31)->days();
        $this->artisan('identities:purge-tombstones')->assertSuccessful();
        $this->assertNull(User::withTrashed()->find($target->id));
        $progress = $this->actingAs($admin)->getJson('/api/admin/identity-lifecycle')->assertOk()
            ->assertJsonPath('data.0.pending_count', 1)->assertJsonPath('data.0.retention_expired', true);
        $purgedAt = $progress->json('data.0.provider_purged_at');
        $this->assertNotNull($purgedAt);
        $this->withBasicAuth((string) $unavailable->id, $unavailableSecret)
            ->getJson('/api/reconciliation/identity-tombstones')->assertOk()
            ->assertJsonPath('data.0.id', $id)->assertJsonPath('data.0.provider_purged_at', $purgedAt);
        $ack = '/api/reconciliation/identity-tombstones/'.$id.'/acknowledgement';
        $first = $this->putJson($ack)->assertOk()->json('acknowledgement.acknowledged_at');
        $this->assertNotNull($first);
        $this->travel(1)->minute();
        $this->putJson($ack)->assertOk()->assertJsonPath('acknowledgement.acknowledged_at', $first);
        $this->actingAs($admin)->getJson('/api/admin/identity-lifecycle')->assertOk()
            ->assertJsonPath('data.0.pending_count', 0)->assertJsonPath('data.0.provider_purged_at', $purgedAt);
    }
}
