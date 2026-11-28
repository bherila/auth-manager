<?php

namespace Tests\Feature;

use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Models\PasskeyCredential;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Tests\TestCase;

/**
 * Directory administration helps someone back in: it removes passkeys a person lost or no longer
 * trusts, mails them a password reset link, and opens one person by the subject applications know
 * them by.
 */
final class DirectoryAdminRecoveryTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        Mail::fake();
    }

    public function test_the_directory_names_each_person_by_subject_and_counts_their_passkeys(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create();
        $this->passkeys($person, 2);

        $response = $this->actingAs($admin)->getJson('/api/admin/users')->assertOk();
        $users = collect($response->json('users'))->keyBy('id');

        $this->assertSame($person->fresh()->providerSubject(), $users->get($person->id)['subject']);
        $this->assertSame(2, $users->get($person->id)['passkey_count']);
        $this->assertSame(0, $users->get($admin->id)['passkey_count']);
        $this->assertFalse($response->json('password_reset_available'));

        config(['auth-manager.sign_in.password_reset' => true]);
        $this->getJson('/api/admin/users')->assertJsonPath('password_reset_available', true);
    }

    public function test_removing_passkeys_needs_recent_proof_and_ends_every_session(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create(['credential_version' => 4]);
        $this->passkeys($person, 2);
        DB::table('sessions')->insert(['id' => 'synthetic-session', 'user_id' => $person->id, 'payload' => '', 'last_activity' => now()->timestamp]);

        $this->actingAs($admin)->withSession([EnsureCredentialVersion::SESSION_KEY => (int) $admin->credential_version])
            ->deleteJson($this->passkeysUrl($person), ['expected_revision' => $this->revision($person)])
            ->assertForbidden();
        $this->assertSame(2, $this->passkeyCount($person));

        $this->confirmed($admin)
            ->deleteJson($this->passkeysUrl($person), ['expected_revision' => $this->revision($person)])
            ->assertOk()
            ->assertJsonPath('user.passkey_count', 0);

        $this->assertSame(0, $this->passkeyCount($person));
        $this->assertSame(5, (int) $person->fresh()->credential_version);
        $this->assertSame(0, DB::table('sessions')->where('user_id', $person->id)->count());
        $audit = AuthAuditLog::query()->where('event', DirectoryAdminService::EVENT_PASSKEYS_REMOVED)->sole();
        $this->assertSame($person->id, (int) $audit->user_id);
        $this->assertSame($admin->id, (int) $audit->acting_user_id);
        $this->assertSame(['passkeys_removed' => 2], $audit->metadata);
    }

    public function test_removing_passkeys_from_someone_who_has_none_changes_nothing(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create(['credential_version' => 4]);

        $this->confirmed($admin)
            ->deleteJson($this->passkeysUrl($person), ['expected_revision' => $this->revision($person)])
            ->assertOk();

        $this->assertSame(4, (int) $person->fresh()->credential_version);
        $this->assertSame(0, AuthAuditLog::query()->where('event', DirectoryAdminService::EVENT_PASSKEYS_REMOVED)->count());
    }

    public function test_an_administrator_manages_their_own_passkeys_from_account_settings(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        User::factory()->create(['user_role' => 'admin']);
        $this->passkeys($admin, 1);

        $this->confirmed($admin)
            ->deleteJson($this->passkeysUrl($admin), ['expected_revision' => $this->revision($admin)])
            ->assertUnprocessable();

        $this->assertSame(1, $this->passkeyCount($admin));
    }

    public function test_a_stale_revision_removes_no_passkeys(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create();
        $this->passkeys($person, 1);
        $revision = $this->revision($person);
        $person->forceFill(['email' => 'changed@example.test'])->save();

        $this->confirmed($admin)
            ->deleteJson($this->passkeysUrl($person), ['expected_revision' => $revision])
            ->assertConflict();

        $this->assertSame(1, $this->passkeyCount($person));
    }

    public function test_a_recovery_link_is_mailed_only_where_self_service_reset_is_on(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create(['email' => 'person@example.test']);

        $this->actingAs($admin)->postJson($this->recoveryUrl($person))->assertUnprocessable();
        Mail::assertNothingSent();

        config(['auth-manager.sign_in.password_reset' => true]);
        $this->postJson($this->recoveryUrl($person))->assertOk();

        Mail::assertSent(PasswordResetConfirmationMail::class, fn (PasswordResetConfirmationMail $mail): bool => $mail->hasTo('person@example.test')
            && str_contains($mail->resetUrl, rawurlencode('person@example.test')));
        $this->assertSame(1, DB::table('password_reset_tokens')->where('email', 'person@example.test')->count());
        $audit = AuthAuditLog::query()->where('event', DirectoryAdminService::EVENT_RECOVERY_SENT)->sole();
        $this->assertSame($person->id, (int) $audit->user_id);
        $this->assertSame($admin->id, (int) $audit->acting_user_id);

        $this->postJson($this->recoveryUrl($person))->assertUnprocessable();
        Mail::assertSentCount(1);
    }

    public function test_a_disabled_person_gets_no_recovery_link(): void
    {
        config(['auth-manager.sign_in.password_reset' => true]);
        $admin = User::factory()->create(['user_role' => 'admin']);
        $person = User::factory()->create(['disabled_at' => now()]);

        $this->actingAs($admin)->postJson($this->recoveryUrl($person))->assertUnprocessable();

        Mail::assertNothingSent();
        $this->assertSame(0, AuthAuditLog::query()->where('event', DirectoryAdminService::EVENT_RECOVERY_SENT)->count());
    }

    public function test_only_a_provider_administrator_can_use_either_action(): void
    {
        config(['auth-manager.sign_in.password_reset' => true]);
        $user = User::factory()->create();
        $person = User::factory()->create();
        $this->passkeys($person, 1);

        $this->actingAs($user)->deleteJson($this->passkeysUrl($person))->assertForbidden();
        $this->actingAs($user)->postJson($this->recoveryUrl($person))->assertForbidden();

        $this->assertSame(1, $this->passkeyCount($person));
        Mail::assertNothingSent();
    }

    private function passkeys(User $user, int $count): void
    {
        for ($index = 1; $index <= $count; $index++) {
            PasskeyCredential::query()->create([
                'user_id' => $user->getKey(),
                'credential_id' => "synthetic-credential-{$user->id}-{$index}",
                'public_key' => 'synthetic',
                'counter' => 0,
            ]);
        }
    }

    private function passkeyCount(User $user): int
    {
        return PasskeyCredential::query()->where('user_id', $user->getKey())->count();
    }

    private function revision(User $user): string
    {
        return app(ProviderAdministrators::class)->revision($user->fresh());
    }

    private function passkeysUrl(User $user): string
    {
        return "/api/admin/users/{$user->id}/passkeys";
    }

    private function recoveryUrl(User $user): string
    {
        return "/api/admin/users/{$user->id}/recovery";
    }

    private function confirmed(User $admin): static
    {
        return $this->actingAs($admin)->withSession([
            EnsureCredentialVersion::SESSION_KEY => (int) $admin->credential_version,
            ProviderAdministrators::CONFIRMATION_KEY => ['user_id' => (string) $admin->id,
                'credential_version' => (int) $admin->credential_version, 'authenticated_at' => now()->timestamp],
        ]);
    }
}
