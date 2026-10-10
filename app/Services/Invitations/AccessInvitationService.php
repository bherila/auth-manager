<?php

namespace App\Services\Invitations;

use App\Mail\AccessInvitationMail;
use App\Models\AccessInvitation;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Support\StaticApplicationClients;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use SensitiveParameter;
use Throwable;

/**
 * Creating, sending, revoking and accepting invitations to an application.
 *
 * Creating one never looks anybody up: the address is stored and mailed as given, with one template,
 * so the inviter's answer and its timing are the same whether or not the address has an account
 * here. Whether it does is decided only when the link is opened, by its recipient.
 *
 * Tokens are 32 random bytes, shown once (in the email and to the inviter) and stored only as a hash.
 * An invitation is used once, expires, can be revoked, and resending it replaces its token.
 */
final class AccessInvitationService
{
    /** Base64url of 32 bytes, unpadded. */
    public const TOKEN_PATTERN = '[A-Za-z0-9_-]{43}';

    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly InvitationAudit $audit,
        private readonly StaticApplicationClients $clients = new StaticApplicationClients,
    ) {}

    /**
     * @param  array{application_admin: bool, workspaces: list<array{id: string, role: string}>}  $access
     */
    public function create(Request $request, User $inviter, RegisteredApplication $application, string $email, array $access): IssuedInvitation
    {
        $email = trim($email);
        $this->throttle($inviter, $email);
        $token = $this->newToken();

        $invitation = DB::transaction(function () use ($request, $inviter, $application, $email, $access, $token): AccessInvitation {
            $invitation = AccessInvitation::query()->create([
                'application' => $application->key,
                'email' => $email,
                'email_normalized' => AccessInvitation::normalizeEmail($email),
                'token_hash' => AccessInvitation::hashToken($token),
                'inviter_id' => $inviter->getKey(),
                'access' => $access,
                'expires_at' => now()->addDays($this->expiresAfterDays()),
            ]);
            $this->audit->record(InvitationAudit::CREATED, $invitation, $request, $inviter, metadata: ['access' => $access]);
            $this->supersede($request, $inviter, $invitation);

            return $invitation;
        });

        return new IssuedInvitation($invitation, $this->link($token), $this->deliver($request, $inviter, $invitation, $application, $token));
    }

    /** A new token and expiry for a pending or expired invitation; the old link stops working. */
    public function resend(Request $request, User $actor, AccessInvitation $invitation, RegisteredApplication $application): IssuedInvitation
    {
        $this->throttle($actor, $invitation->email);
        $token = $this->newToken();

        $invitation = DB::transaction(function () use ($request, $actor, $invitation, $token): AccessInvitation {
            $locked = AccessInvitation::query()->lockForUpdate()->findOrFail($invitation->getKey());
            if (! in_array($locked->status(), [AccessInvitation::STATUS_PENDING, AccessInvitation::STATUS_EXPIRED], true)) {
                throw ValidationException::withMessages(['invitation' => 'Only a pending or expired invitation can be sent again.']);
            }
            $locked->forceFill([
                'token_hash' => AccessInvitation::hashToken($token),
                'expires_at' => now()->addDays($this->expiresAfterDays()),
            ])->save();
            $this->audit->record(InvitationAudit::RESENT, $locked, $request, $actor);
            $this->supersede($request, $actor, $locked);

            return $locked;
        });

        return new IssuedInvitation($invitation, $this->link($token), $this->deliver($request, $actor, $invitation, $application, $token));
    }

    public function revoke(Request $request, User $actor, AccessInvitation $invitation): void
    {
        DB::transaction(function () use ($request, $actor, $invitation): void {
            $locked = AccessInvitation::query()->lockForUpdate()->findOrFail($invitation->getKey());
            if ($locked->accepted_at !== null) {
                throw ValidationException::withMessages(['invitation' => 'This invitation was already accepted. Change the person\'s access instead.']);
            }
            if ($locked->revoked_at !== null) {
                return;
            }
            $locked->forceFill(['revoked_at' => now(), 'revoked_by' => $actor->getKey()])->save();
            $this->audit->record(InvitationAudit::REVOKED, $locked, $request, $actor);
        });
    }

    /**
     * Revoke every other pending invitation to the same address for the same application, so only the
     * newest link works. Matches on invitations alone, never on accounts, so it reveals nothing more
     * than creating one does. Called inside the creating or resending transaction.
     */
    private function supersede(Request $request, User $actor, AccessInvitation $current): void
    {
        $older = AccessInvitation::query()
            ->where('application', $current->application)
            ->where('email_normalized', $current->email_normalized)
            ->whereKeyNot($current->getKey())
            ->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '>', now())
            ->lockForUpdate()->get();
        foreach ($older as $invitation) {
            $invitation->forceFill(['revoked_at' => now(), 'revoked_by' => $actor->getKey()])->save();
            $this->audit->record(InvitationAudit::REVOKED, $invitation, $request, $actor, metadata: [
                'reason' => 'superseded', 'superseded_by' => $current->getKey(),
            ]);
        }
    }

    /** The pending invitation this token opens, or null for any other token: one answer for all. */
    public function findPending(#[SensitiveParameter] string $token): ?AccessInvitation
    {
        if (preg_match('/^'.self::TOKEN_PATTERN.'$/D', $token) !== 1) {
            return null;
        }
        $invitation = AccessInvitation::query()->where('token_hash', AccessInvitation::hashToken($token))->first();

        return $invitation instanceof AccessInvitation && $invitation->isPending() ? $invitation : null;
    }

    /** The provider account with the invited address, case-insensitively, deleted or not. */
    public function accountFor(AccessInvitation $invitation, bool $lock = false): ?User
    {
        $query = User::withTrashed()->whereRaw('lower(email) = ?', [$invitation->email_normalized]);
        if ($lock) {
            $query->lockForUpdate();
        }

        return $query->first();
    }

    /**
     * Accept, in this order under the invitation's lock: mark it used, then admit the person to the
     * application's sign-in clients. Roles are applied after this commits, by {@see InvitationRoles}.
     *
     * Either `$signedIn` is the active account with the invited address, or `$newAccount` creates
     * one with that address when none exists. Anything else, or an invitation that stopped being
     * pending, throws without changing anything.
     *
     * @param  array{name: string, password: string}|null  $newAccount
     * @return array{0: User, 1: bool} the person, and whether their account was created now
     *
     * @throws InvitationUnavailable
     */
    public function accept(Request $request, AccessInvitation $invitation, ?User $signedIn, #[SensitiveParameter] ?array $newAccount): array
    {
        return DB::transaction(function () use ($request, $invitation, $signedIn, $newAccount): array {
            $locked = AccessInvitation::query()->lockForUpdate()->find($invitation->getKey());
            if (! $locked instanceof AccessInvitation || ! $locked->isPending()) {
                throw new InvitationUnavailable('not_pending');
            }
            $clientIds = $this->clientIds($locked->application);
            if ($clientIds === []) {
                throw new InvitationUnavailable('application_unavailable');
            }

            $account = $this->accountFor($locked, true);
            if ($newAccount !== null) {
                if ($account !== null || $signedIn !== null) {
                    throw new InvitationUnavailable('account_exists');
                }
                try {
                    $person = User::query()->create([
                        'name' => $newAccount['name'], 'email' => $locked->email,
                        'password' => $newAccount['password'], 'user_role' => 'user',
                    ]);
                } catch (QueryException) {
                    // The address was taken by an account created at the same moment.
                    throw new InvitationUnavailable('account_exists');
                }
                // Opening the emailed link is proof of the address.
                $person->forceFill(['email_verified_at' => now()])->save();
                $created = true;
            } else {
                if (! $account instanceof User || ! $signedIn instanceof User
                    || $account->getKey() !== $signedIn->getKey() || ! $account->canLogin()) {
                    throw new InvitationUnavailable('wrong_account');
                }
                $person = $account;
                $created = false;
            }

            $locked->forceFill(['accepted_at' => now(), 'accepted_user_id' => $person->getKey()])->save();
            $granted = [];
            foreach ($clientIds as $clientId) {
                if ($this->grants->grant((string) $person->getKey(), $clientId)) {
                    $granted[] = $clientId;
                }
            }
            $this->audit->record(InvitationAudit::ACCEPTED, $locked, $request, $person, $person, metadata: [
                'account_created' => $created, 'oauth_client_ids' => $granted,
            ]);

            return [$person, $created];
        });
    }

    public function link(#[SensitiveParameter] string $token): string
    {
        return route('invitations.show', ['token' => $token]);
    }

    public function expiresAfterDays(): int
    {
        return max(1, (int) config('delegated-access.invitations.expires_after_days', 7));
    }

    /**
     * @return list<string> the eligible static clients of the enabled registration
     */
    private function clientIds(string $application): array
    {
        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->first();
        if (! $registration instanceof RegisteredApplication) {
            return [];
        }

        return $registration->clients()->get()
            ->filter(fn (PassportClient $client): bool => $this->clients->eligible($client))
            ->map(fn (PassportClient $client): string => (string) $client->getKey())
            ->values()->all();
    }

    private function deliver(Request $request, User $actor, AccessInvitation $invitation, RegisteredApplication $application, #[SensitiveParameter] string $token): bool
    {
        try {
            Mail::to($invitation->email)->send(new AccessInvitationMail($application->name, $this->link($token), $this->expiresAfterDays()));
            $sent = true;
        } catch (Throwable $failure) {
            // Never the message or the transport's text: either could carry the link or a credential.
            Log::warning('An invitation email could not be sent.', ['invitation_id' => $invitation->getKey(), 'exception' => $failure::class]);
            $sent = false;
        }
        if ($sent) {
            $invitation->forceFill(['last_sent_at' => now(), 'send_count' => $invitation->send_count + 1])->save();
        }
        $this->audit->record(InvitationAudit::SENT, $invitation, $request, $actor, succeeded: $sent);

        return $sent;
    }

    /**
     * Per inviter and per recipient address, counted whether or not that address has an account.
     *
     * @throws ValidationException
     */
    private function throttle(User $actor, string $email): void
    {
        $inviterKey = 'access-invite-inviter:'.$actor->getKey();
        $recipientKey = 'access-invite-recipient:'.hash('sha256', AccessInvitation::normalizeEmail($email));
        $perInviter = max(1, (int) config('delegated-access.invitations.per_inviter_per_hour', 20));
        $perRecipient = max(1, (int) config('delegated-access.invitations.per_recipient_per_day', 5));
        if (RateLimiter::tooManyAttempts($inviterKey, $perInviter)) {
            throw ValidationException::withMessages(['email' => 'You have sent too many invitations. Try again later.']);
        }
        if (RateLimiter::tooManyAttempts($recipientKey, $perRecipient)) {
            throw ValidationException::withMessages(['email' => 'Too many invitations went to this address today. Try again tomorrow.']);
        }
        RateLimiter::hit($inviterKey, 3600);
        RateLimiter::hit($recipientKey, 86400);
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
