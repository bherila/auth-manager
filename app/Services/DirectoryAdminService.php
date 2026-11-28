<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Models\PasskeyCredential;
use BWH\AuthManager\Models\IdentityTombstone;
use BWH\AuthManager\Models\IdentityTombstoneClient;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\Mount;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Throwable;

class DirectoryAdminService
{
    public const EVENT_USER_CREATED = 'directory_user_created';

    public const EVENT_NAME_CHANGED = 'directory_name_changed';

    public const EVENT_EMAIL_CHANGED = 'directory_email_changed';

    public const EVENT_USER_DISABLED = 'directory_user_disabled';

    public const EVENT_USER_ENABLED = 'directory_user_enabled';

    public const EVENT_PASSWORD_RESET = 'directory_password_reset';

    public const EVENT_CLIENT_GRANTED = 'directory_client_granted';

    public const EVENT_CLIENT_REVOKED = 'directory_client_revoked';

    public const EVENT_USER_TOMBSTONED = 'directory_user_tombstoned';

    public const EVENT_ADMINISTRATOR_CHANGED = 'provider_administrator_changed';

    public const EVENT_PASSKEYS_REMOVED = 'directory_passkeys_removed';

    public const EVENT_RECOVERY_SENT = 'directory_recovery_sent';

    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly DirectoryAdminAuditLogger $audit,
        private readonly ProviderAdministrators $administrators,
        private readonly IdentityRetirement $retirement,
        private readonly EmailProof $emailProof,
    ) {}

    /**
     * @param  array{name:string,email:string,password:string,enabled:bool,client_ids:list<string>}  $attributes
     */
    public function create(Request $request, User $actor, array $attributes): User
    {
        $clientIds = $this->activeClientIds($attributes['client_ids']);

        return DB::transaction(function () use ($request, $actor, $attributes, $clientIds): User {
            $this->administrators->actor($this->administrators->lockDirectory(), $actor, $request);
            $user = User::query()->create([
                'name' => $attributes['name'],
                'email' => $attributes['email'],
                'password' => $attributes['password'],
                'user_role' => 'user',
                'disabled_at' => $attributes['enabled'] ? null : now(),
            ]);

            foreach ($clientIds as $clientId) {
                $this->grants->grant((string) $user->getKey(), $clientId);
            }

            $this->audit->record($request, $actor, $user, self::EVENT_USER_CREATED, [
                'enabled' => $attributes['enabled'],
                'oauth_client_ids' => $clientIds,
            ]);
            app(AccessGroupService::class)->joinDefaultGroups($user, AccessGroupService::JOINED_BY_DIRECTORY_ADMIN);

            return $user;
        }, 3);
    }

    public function changeName(Request $request, User $actor, User $target, string $name): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $name): User {
            $locked = $this->lock($request, $actor, $target);

            if ($locked->name !== $name) {
                $previous = $locked->name;
                $locked->forceFill(['name' => $name])->save();
                // Consumers project this name, so a rename can impersonate. Keep both
                // values so the audit trail shows what changed and can be reverted.
                $this->audit->record($request, $actor, $locked, self::EVENT_NAME_CHANGED,
                    ['previous_name' => $previous, 'name' => $name]);
            }

            return $locked;
        }, 3);
    }

    public function changeEmail(Request $request, User $actor, User $target, string $email): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $email): User {
            $locked = $this->lock($request, $actor, $target);

            if ($locked->email !== $email) {
                $formerEmail = (string) $locked->email;
                $locked->forceFill([
                    'email' => $email,
                    'email_verified_at' => null,
                ])->save();
                // Codes and reset links mailed to the former address must neither finish a
                // sign-in nor prove the new one.
                $this->emailProof->forgetAddress($locked, $formerEmail);
                $this->audit->record($request, $actor, $locked, self::EVENT_EMAIL_CHANGED);
            }

            return $locked;
        }, 3);
    }

    public function changeAdministrator(Request $request, User $actor, User $target, bool $administrator, string $expectedRevision): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $administrator, $expectedRevision): User {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request, recent: true);
            $locked = $this->administrators->target($users, $target);
            $this->administrators->expectRevision($locked, $expectedRevision);
            if ($administrator && $locked->isTestLogin()) {
                throw ValidationException::withMessages(['user' => 'Test logins cannot hold provider-administrator authority.']);
            }
            if ($administrator && ! $locked->canLogin()) {
                throw ValidationException::withMessages(['user' => 'Enable this account before granting provider-administrator authority.']);
            }
            if ($locked->hasRole('admin') === $administrator) {
                return $locked;
            }
            if (! $administrator) {
                $this->administrators->preserveRecoveryAdministrator($users, $locked, 'demoted');
            }
            $before = $locked->roleNames();
            $after = $administrator ? [...$before, 'admin'] : array_values(array_diff($before, ['admin']));
            // Removing provider administration does not disable ordinary sign-in.
            if (! $administrator && ! in_array('user', $after, true)) {
                $after[] = 'user';
            }
            $locked->user_role = implode(',', $after);
            $this->administrators->invalidateAuthority($locked);
            $this->audit->record($request, $actor, $locked, self::EVENT_ADMINISTRATOR_CHANGED, [
                'administrator' => $administrator, 'previous_roles' => $before, 'roles' => $after,
            ]);

            return $locked;
        }, 3);
    }

    public function disable(Request $request, User $actor, User $target, ?string $expectedRevision = null): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $expectedRevision): User {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $locked = $this->administrators->target($users, $target);
            $this->administrators->expectRevision($locked, $expectedRevision);

            if ($locked->disabled_at !== null) {
                return $locked;
            }

            $this->administrators->preserveRecoveryAdministrator($users, $locked, 'disabled');

            $locked->disabled_at = now();
            $this->administrators->invalidateAuthority($locked);
            $this->audit->record($request, $actor, $locked, self::EVENT_USER_DISABLED);

            return $locked;
        }, 3);
    }

    public function enable(Request $request, User $actor, User $target): User
    {
        return DB::transaction(function () use ($request, $actor, $target): User {
            $locked = $this->lock($request, $actor, $target);

            if ($locked->canLogin()) {
                return $locked;
            }

            if (! $locked->hasRole('user') && ! $locked->hasRole('admin')) {
                $locked->user_role = 'user';
            }

            $locked->disabled_at = null;
            $locked->save();
            $this->audit->record($request, $actor, $locked, self::EVENT_USER_ENABLED);

            return $locked;
        }, 3);
    }

    public function resetPassword(Request $request, User $actor, User $target, string $password): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $password): User {
            $locked = $this->lock($request, $actor, $target);
            $locked->password = $password;
            $this->administrators->invalidateAuthority($locked);
            $this->audit->record($request, $actor, $locked, self::EVENT_PASSWORD_RESET);

            return $locked;
        }, 3);
    }

    /**
     * Remove every passkey a person holds, for someone who lost the device or whose passkey may be
     * in someone else's hands. Sessions, remember cookies, trusted devices and OAuth credentials
     * end with them, since any of those may have been established with the passkey. Needs proof
     * from a credential presented in the last five minutes. A person's own passkeys are managed
     * from their account settings, never here.
     */
    public function removePasskeys(Request $request, User $actor, User $target, ?string $expectedRevision = null): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $expectedRevision): User {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request, recent: true);
            $locked = $this->administrators->target($users, $target);
            $this->administrators->expectRevision($locked, $expectedRevision);
            if ($locked->getKey() === $actor->getKey()) {
                throw ValidationException::withMessages(['user' => 'Manage your own passkeys from your account settings.']);
            }

            $removed = PasskeyCredential::query()->where('user_id', $locked->getKey())->delete();
            if ($removed === 0) {
                return $locked;
            }

            $this->administrators->invalidateAuthority($locked);
            $this->audit->record($request, $actor, $locked, self::EVENT_PASSKEYS_REMOVED, ['passkeys_removed' => $removed]);

            return $locked;
        }, 3);
    }

    /**
     * Mail a password reset link to the person's current address, the same link and mail
     * self-service reset sends. Only on an instance that offers self-service reset, since the
     * link opens that page, and only to an active account that may hold a local password.
     * The broker's per-person throttle applies.
     */
    public function sendRecovery(Request $request, User $actor, User $target): User
    {
        $locked = DB::transaction(fn (): User => $this->lock($request, $actor, $target), 3);

        if (! config('auth-manager.sign_in.password_reset')) {
            throw ValidationException::withMessages(['user' => 'Self-service password reset is off on this instance. Set a temporary password instead.']);
        }
        if (! $locked->canLogin()) {
            throw ValidationException::withMessages(['user' => 'Re-enable this person before sending a recovery link.']);
        }
        if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($locked, $request)) {
            throw ValidationException::withMessages(['user' => 'This account cannot hold a password, so there is nothing to recover by email.']);
        }

        $failed = false;
        $status = Password::broker(Mount::embedded() ? Mount::EMBEDDED_USER_PROVIDER : null)
            ->sendResetLink(['email' => $locked->email], function (User $user, string $token) use (&$failed): void {
                $url = strtr((string) config('bherila-auth.password_resets.reset_url'), [
                    '{token}' => rawurlencode($token),
                    '{email}' => rawurlencode($user->email),
                ]);
                try {
                    Mail::to($user->email)->send(new PasswordResetConfirmationMail($user, $url, (string) config('app.name')));
                } catch (Throwable $exception) {
                    report($exception);
                    $failed = true;
                }
            });

        if ($status === Password::RESET_THROTTLED) {
            throw ValidationException::withMessages(['user' => 'A recovery link was sent to this person moments ago. Wait a minute before sending another.']);
        }
        if ($status !== Password::RESET_LINK_SENT || $failed) {
            throw ValidationException::withMessages(['user' => 'The recovery email could not be sent. Try again, or set a temporary password.']);
        }

        $this->audit->record($request, $actor, $locked, self::EVENT_RECOVERY_SENT);

        return $locked;
    }

    public function tombstone(Request $request, User $actor, User $target, ?string $expectedRevision = null): IdentityTombstone
    {
        return DB::transaction(function () use ($request, $actor, $target, $expectedRevision): IdentityTombstone {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $locked = $this->administrators->target($users, $target);
            $this->administrators->expectRevision($locked, $expectedRevision);
            $this->administrators->preserveRecoveryAdministrator($users, $locked, 'deleted');

            $tombstone = $this->retirement->retire($locked);
            $this->audit->record($request, $actor, $locked, self::EVENT_USER_TOMBSTONED, [
                'identity_tombstone_id' => $tombstone->public_id,
                'purge_after' => $tombstone->purge_after->toISOString(),
                'expected_oauth_clients' => $tombstone->clients
                    ->map(static fn (IdentityTombstoneClient $client): array => [
                        'id' => (string) $client->oauth_client_id,
                        'name' => (string) $client->oauth_client_name,
                    ])
                    ->all(),
            ]);

            return $tombstone;
        }, 3);
    }

    public function grantClient(Request $request, User $actor, User $target, PassportClient $client): User
    {
        $this->assertActiveClient($client);

        return DB::transaction(function () use ($request, $actor, $target, $client): User {
            $locked = $this->lock($request, $actor, $target);

            if ($this->grants->grant((string) $locked->getKey(), (string) $client->getKey())) {
                $this->audit->record($request, $actor, $locked, self::EVENT_CLIENT_GRANTED, [
                    'oauth_client_id' => (string) $client->getKey(),
                ]);
            }

            return $locked;
        }, 3);
    }

    public function revokeClient(Request $request, User $actor, User $target, PassportClient $client): User
    {
        return DB::transaction(function () use ($request, $actor, $target, $client): User {
            $locked = $this->lock($request, $actor, $target);
            $removed = $this->grants->revoke((string) $locked->getKey(), (string) $client->getKey());

            if ($removed) {
                $this->audit->record($request, $actor, $locked, self::EVENT_CLIENT_REVOKED, [
                    'oauth_client_id' => (string) $client->getKey(),
                ]);
            }

            return $locked;
        }, 3);
    }

    private function lock(Request $request, User $actor, User $target): User
    {
        $users = $this->administrators->lockDirectory();
        $this->administrators->actor($users, $actor, $request);

        return $this->administrators->target($users, $target);
    }

    /**
     * @param  list<string>  $requested
     * @return list<string>
     */
    private function activeClientIds(array $requested): array
    {
        $requested = array_values(array_unique($requested));
        $found = PassportClient::query()
            ->whereIn('id', $requested)
            ->where('revoked', false)
            ->pluck('id')
            ->map(static fn (mixed $id): string => (string) $id)
            ->all();

        if (count($found) !== count($requested)) {
            throw ValidationException::withMessages([
                'client_ids' => 'Every selected application must be an active OAuth client.',
            ]);
        }

        return $found;
    }

    private function assertActiveClient(PassportClient $client): void
    {
        if ($client->revoked) {
            throw ValidationException::withMessages([
                'client' => 'The selected application is not active.',
            ]);
        }
    }
}
