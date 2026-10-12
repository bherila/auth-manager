<?php

namespace App\Services\Invitations;

use App\Mail\AccessInvitationMail;
use App\Models\AccessInvitation;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Support\ApplicationInvitations;
use App\Support\StaticApplicationClients;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use SensitiveParameter;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
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
 *
 * An application may also request one for itself ({@see RequestingClient}): it carries no roles,
 * admits only to the requesting client, is managed only through that client, and its link is
 * returned to the application every time, so opening it never proves the address.
 */
final class AccessInvitationService
{
    /** Base64url of 32 bytes, unpadded. */
    public const TOKEN_PATTERN = '[A-Za-z0-9_-]{43}';

    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly InvitationAudit $audit,
        private readonly StaticApplicationClients $clients = new StaticApplicationClients,
        private readonly ApplicationInvitations $applicationInvitations = new ApplicationInvitations,
    ) {}

    /**
     * @param  array{application_admin: bool, workspaces: list<array{id: string, role: string}>}  $access
     */
    public function create(Request $request, User $inviter, RegisteredApplication $application, string $email, array $access, ?RequestingClient $via = null): IssuedInvitation
    {
        $email = trim($email);
        if ($via !== null) {
            // Admission only: whatever the caller passed, an application's own invitation carries no roles.
            $access = ['application_admin' => false, 'workspaces' => []];
        }
        $this->throttle($inviter, $email, $via);
        $token = $this->newToken();

        $normalized = AccessInvitation::normalizeEmail($email);
        $invitation = $this->serialized(fn (): AccessInvitation => DB::transaction(function () use ($request, $inviter, $application, $email, $normalized, $access, $token, $via): AccessInvitation {
            // Older invitations give up the pending key before this one takes it.
            $superseded = $this->supersede($inviter, $application->key, $normalized, null, $via);
            $invitation = AccessInvitation::query()->create([
                'application' => $application->key,
                'requesting_client_id' => $via?->clientId,
                'email' => $email,
                'email_normalized' => $normalized,
                'token_hash' => AccessInvitation::hashToken($token),
                'pending_key' => AccessInvitation::pendingKey($application->key, $normalized, $via?->clientId),
                'link_handed_over' => true,
                'inviter_id' => $inviter->getKey(),
                'inviter_credential_version' => (int) $inviter->credential_version,
                'access' => $access,
                'expires_at' => now()->addDays($this->expiresAfterDays()),
            ]);
            // Only the shape: workspace ids and role names are the application's, and the invitation
            // row that holds them goes when it is purged; the audit row stays.
            $this->audit->record(InvitationAudit::CREATED, $invitation, $request, $inviter, metadata: [
                'application_admin' => $access['application_admin'], 'workspace_count' => count($access['workspaces']),
                ...$this->viaMetadata($via, $inviter),
            ]);
            $this->auditSuperseded($request, $inviter, $superseded, $invitation, $via);

            return $invitation;
        }), $via);

        return new IssuedInvitation($invitation, $this->link($token), $this->deliver($request, $inviter, $invitation, $application, $token, $via));
    }

    /** A new token and expiry for a pending or expired invitation; the old link stops working. */
    public function resend(Request $request, User $actor, AccessInvitation $invitation, RegisteredApplication $application, ?RequestingClient $via = null): IssuedInvitation
    {
        $this->throttle($actor, $invitation->email, $via);
        $token = $this->newToken();

        $invitation = $this->serialized(fn (): AccessInvitation => DB::transaction(function () use ($request, $actor, $invitation, $token, $via): AccessInvitation {
            $locked = AccessInvitation::query()->lockForUpdate()->findOrFail($invitation->getKey());
            $this->assertSamePath($locked, $via);
            if (! in_array($locked->status(), [AccessInvitation::STATUS_PENDING, AccessInvitation::STATUS_EXPIRED], true)) {
                throw $via === null
                    ? ValidationException::withMessages(['invitation' => 'Only a pending or expired invitation can be sent again.'])
                    : new ApplicationInvitationRefused('invitation_not_pending', 409, 'Only a pending or expired invitation can be sent again.');
            }
            $previousInviter = $locked->inviter_id;
            $superseded = $this->supersede($actor, $locked->application, $locked->email_normalized, $locked->getKey(), $via);
            // Whoever resends passed the full write gate just now, so the roles are theirs to give.
            $locked->forceFill([
                'token_hash' => AccessInvitation::hashToken($token),
                'expires_at' => now()->addDays($this->expiresAfterDays()),
                'inviter_id' => $actor->getKey(),
                'inviter_credential_version' => (int) $actor->credential_version,
                'pending_key' => AccessInvitation::pendingKey($locked->application, $locked->email_normalized, $locked->requesting_client_id),
                // A new token: unproven until its email is sent.
                'link_handed_over' => true,
            ])->save();
            $this->audit->record(InvitationAudit::RESENT, $locked, $request, $actor, metadata: [
                'previous_inviter_id' => $previousInviter, ...$this->viaMetadata($via, $actor),
            ]);
            $this->auditSuperseded($request, $actor, $superseded, $locked, $via);

            return $locked;
        }), $via);

        return new IssuedInvitation($invitation, $this->link($token), $this->deliver($request, $actor, $invitation, $application, $token, $via));
    }

    /**
     * @return AccessInvitation the invitation as it now stands: revoked, or as it was if already revoked
     */
    public function revoke(Request $request, User $actor, AccessInvitation $invitation, ?RequestingClient $via = null): AccessInvitation
    {
        return DB::transaction(function () use ($request, $actor, $invitation, $via): AccessInvitation {
            $locked = AccessInvitation::query()->lockForUpdate()->findOrFail($invitation->getKey());
            $this->assertSamePath($locked, $via);
            if ($locked->accepted_at !== null) {
                throw $via === null
                    ? ValidationException::withMessages(['invitation' => 'This invitation was already accepted. Change the person\'s access instead.'])
                    : new ApplicationInvitationRefused('invitation_accepted', 409, 'This invitation was already accepted.');
            }
            if ($locked->revoked_at !== null) {
                return $locked;
            }
            $locked->forceFill(['revoked_at' => now(), 'revoked_by' => $actor->getKey(), 'pending_key' => null])->save();
            $this->audit->record(InvitationAudit::REVOKED, $locked, $request, $actor, metadata: $this->viaMetadata($via, $actor));

            return $locked;
        });
    }

    /**
     * Each path manages only its own invitations: the provider's pages never touch one an application
     * requested, and an application only those requested through its own client.
     *
     * @throws ApplicationInvitationRefused|NotFoundHttpException
     */
    private function assertSamePath(AccessInvitation $invitation, ?RequestingClient $via): void
    {
        if ($invitation->requesting_client_id === $via?->clientId) {
            return;
        }
        if ($via !== null) {
            throw new ApplicationInvitationRefused('invitation_not_found', 404, 'No such invitation for this client.');
        }
        abort(404);
    }

    /**
     * Audit metadata for an application's own invitation: the requesting client and the actor's
     * provider subject, as its assertion named it.
     *
     * @return array<string, mixed>
     */
    private function viaMetadata(?RequestingClient $via, User $actor): array
    {
        return $via === null ? [] : [
            'via' => 'application', 'oauth_client_id' => $via->clientId,
            'actor_subject' => (string) $actor->getKey(), 'link_returned' => true,
        ];
    }

    /**
     * Free the pending key for this application and address: every other invitation holding it gives
     * it up, and one still pending is revoked, so only the newest link works. Matches on invitations
     * alone, never on accounts, so it reveals nothing more than creating one does. Runs inside the
     * creating or resending transaction, before the key is taken.
     *
     * @return list<AccessInvitation> the invitations it revoked
     */
    private function supersede(User $actor, string $application, string $normalized, ?int $except, ?RequestingClient $via = null): array
    {
        // Only invitations from the same path: an application's own never revokes one sent from the
        // provider's pages (which may carry roles), nor one requested through another client.
        $holders = AccessInvitation::query()
            ->where('application', $application)
            ->where('email_normalized', $normalized)
            ->when($via === null, fn ($query) => $query->whereNull('requesting_client_id'),
                fn ($query) => $query->where('requesting_client_id', $via->clientId))
            ->whereNotNull('pending_key')
            ->when($except !== null, fn ($query) => $query->whereKeyNot($except))
            ->lockForUpdate()->get();
        $revoked = [];
        foreach ($holders as $invitation) {
            $pending = $invitation->isPending();
            $invitation->forceFill(['pending_key' => null, ...($pending ? ['revoked_at' => now(), 'revoked_by' => $actor->getKey()] : [])])->save();
            if ($pending) {
                $revoked[] = $invitation;
            }
        }

        return $revoked;
    }

    /**
     * @param  list<AccessInvitation>  $superseded
     */
    private function auditSuperseded(Request $request, User $actor, array $superseded, AccessInvitation $by, ?RequestingClient $via = null): void
    {
        foreach ($superseded as $invitation) {
            $this->audit->record(InvitationAudit::REVOKED, $invitation, $request, $actor, metadata: [
                'reason' => 'superseded', 'superseded_by' => $by->getKey(), ...$this->viaMetadata($via, $actor),
            ]);
        }
    }

    /**
     * Run a create or resend; if a concurrent one took the pending key first, run it once more, when
     * it supersedes that one. A second loss fails closed, with no invitation changed.
     *
     * @template T
     *
     * @param  \Closure(): T  $work
     * @return T
     */
    private function serialized(\Closure $work, ?RequestingClient $via = null): mixed
    {
        try {
            return $work();
        } catch (UniqueConstraintViolationException) {
            try {
                return $work();
            } catch (UniqueConstraintViolationException) {
                throw $via === null
                    ? ValidationException::withMessages(['email' => 'Another invitation to this address was being sent at the same moment. Try again.'])
                    : new ApplicationInvitationRefused('concurrent_invitation', 409, 'Another invitation to this address was being sent at the same moment. Try again.');
            }
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

    /**
     * The provider account with the invited address, case-insensitively, deleted or not.
     *
     * Fails closed when more than one account matches (a database whose unique index is case
     * sensitive can hold case variants): choosing one would bind the invitation to whichever row
     * came back first. With none, no case variant exists, so creating an account is safe.
     *
     * @throws InvitationUnavailable `ambiguous_account`
     */
    public function accountFor(AccessInvitation $invitation, bool $lock = false): ?User
    {
        $query = User::withTrashed()->whereRaw('lower(email) = ?', [$invitation->email_normalized])->orderBy('id')->limit(2);
        if ($lock) {
            $query->lockForUpdate();
        }
        $matches = $query->get();
        if ($matches->count() > 1) {
            throw new InvitationUnavailable('ambiguous_account');
        }

        return $matches->first();
    }

    /**
     * Accept, in this order under the invitation's lock: mark it used, then admit the person to the
     * application's sign-in clients. Roles are applied after this commits, by {@see InvitationRoles}.
     *
     * Either `$signedIn` is the active account with the invited address, or `$newAccount` creates
     * one with that address when none exists. Anything else, or an invitation that stopped being
     * pending, throws without changing anything.
     *
     * @param  string  $tokenHash  the hash of the token the request presented
     * @param  array{name: string, password: string}|null  $newAccount
     * @return array{0: User, 1: bool} the person, and whether their account was created now
     *
     * @throws InvitationUnavailable
     */
    public function accept(Request $request, AccessInvitation $invitation, string $tokenHash, ?User $signedIn, #[SensitiveParameter] ?array $newAccount): array
    {
        return DB::transaction(function () use ($request, $invitation, $tokenHash, $signedIn, $newAccount): array {
            $locked = AccessInvitation::query()->lockForUpdate()->find($invitation->getKey());
            // The presented token must still be the current one: a resend that committed after the link
            // was opened replaced it, and the old link must not accept.
            if (! $locked instanceof AccessInvitation || ! $locked->isPending() || ! hash_equals($locked->token_hash, $tokenHash)) {
                throw new InvitationUnavailable('not_pending');
            }
            // An application's own invitation admits to its requesting client alone, and only while that
            // client may still request invitations for the application.
            $clientIds = $locked->requesting_client_id !== null
                ? array_values(array_filter([$this->applicationInvitations->admittingClient($locked)]))
                : $this->clientIds($locked->application);
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
                // Opening the emailed link is proof of the address; a link handed to the inviter is not.
                if (! $locked->link_handed_over) {
                    $person->forceFill(['email_verified_at' => now()])->save();
                }
                $created = true;
            } else {
                if (! $account instanceof User || ! $signedIn instanceof User
                    || $account->getKey() !== $signedIn->getKey() || ! $account->canLogin()) {
                    throw new InvitationUnavailable('wrong_account');
                }
                $person = $account;
                $created = false;
            }

            $locked->forceFill(['accepted_at' => now(), 'accepted_user_id' => $person->getKey(), 'pending_key' => null])->save();
            $granted = [];
            foreach ($clientIds as $clientId) {
                if ($this->grants->grant((string) $person->getKey(), $clientId)) {
                    $granted[] = $clientId;
                }
            }
            $this->audit->record(InvitationAudit::ACCEPTED, $locked, $request, $person, $person, metadata: [
                'account_created' => $created, 'oauth_client_ids' => $granted, 'link_handed_over' => $locked->link_handed_over,
                ...($locked->requesting_client_id === null ? [] : [
                    'via' => 'application', 'oauth_client_id' => $locked->requesting_client_id,
                    'actor_subject' => $locked->inviter_id === null ? null : (string) $locked->inviter_id,
                ]),
            ]);

            return [$person, $created];
        });
    }

    /**
     * Whether the default mailer delivers mail. `log` writes the whole message, link included, to the
     * application log, and `array` keeps it in memory; either would report an invitation sent that
     * nobody received. A failover or round-robin mailer counts only if none of its mailers is one.
     */
    public static function mailDelivers(): bool
    {
        $mailers = (array) config('mail.mailers', []);
        $pending = [(string) config('mail.default')];
        $seen = [];
        while ($pending !== []) {
            $name = array_pop($pending);
            if (isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $transport = $mailers[$name]['transport'] ?? null;
            if (! is_string($transport) || in_array($transport, ['log', 'array'], true)) {
                return false;
            }
            if (in_array($transport, ['failover', 'roundrobin'], true)) {
                array_push($pending, ...array_map('strval', (array) ($mailers[$name]['mailers'] ?? [])));
            }
        }

        return true;
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

    private function deliver(Request $request, User $actor, AccessInvitation $invitation, RegisteredApplication $application, #[SensitiveParameter] string $token, ?RequestingClient $via = null): bool
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
            // An application's own invitation returns its link to the application every time, so
            // opening it never proves the address, sent or not.
            $invitation->forceFill(['last_sent_at' => now(), 'send_count' => $invitation->send_count + 1,
                'link_handed_over' => $via !== null])->save();
        }
        $this->audit->record(InvitationAudit::SENT, $invitation, $request, $actor, succeeded: $sent, metadata: $this->viaMetadata($via, $actor));
        if (! $sent && $via === null) {
            // The link is handed to the inviter only now, to share another way, so whoever opens it
            // is no longer proven to read the invited address.
            $this->audit->record(InvitationAudit::LINK_SHOWN, $invitation, $request, $actor);
        }

        return $sent;
    }

    /**
     * Per inviter and per recipient address, counted whether or not that address has an account.
     *
     * @throws ValidationException
     */
    private function throttle(User $actor, string $email, ?RequestingClient $via = null): void
    {
        $recipientKey = 'access-invite-recipient:'.hash('sha256', AccessInvitation::normalizeEmail($email));
        $perRecipient = max(1, (int) config('delegated-access.invitations.per_recipient_per_day', 5));
        if ($via !== null) {
            $this->throttleApplication($actor, $via, $recipientKey, $perRecipient);

            return;
        }
        $inviterKey = 'access-invite-inviter:'.$actor->getKey();
        $perInviter = max(1, (int) config('delegated-access.invitations.per_inviter_per_hour', 20));
        if (RateLimiter::tooManyAttempts($inviterKey, $perInviter)) {
            throw ValidationException::withMessages(['email' => 'You have sent too many invitations. Try again later.']);
        }
        if (RateLimiter::tooManyAttempts($recipientKey, $perRecipient)) {
            throw ValidationException::withMessages(['email' => 'Too many invitations went to this address today. Try again tomorrow.']);
        }
        RateLimiter::hit($inviterKey, 3600);
        RateLimiter::hit($recipientKey, 86400);
    }

    /**
     * Per requesting client, per actor and per recipient address (that budget shared with the
     * provider's own invitations), counted whether or not the address has an account.
     *
     * @throws ApplicationInvitationRefused
     */
    private function throttleApplication(User $actor, RequestingClient $via, string $recipientKey, int $perRecipient): void
    {
        $limits = [
            'application' => ['application-invite-client:'.$via->clientId, max(1, (int) config('application-invitations.per_application_per_hour', 100)), 3600],
            'actor' => ['application-invite-actor:'.$actor->getKey(), max(1, (int) config('application-invitations.per_actor_per_hour', 20)), 3600],
            'recipient' => [$recipientKey, $perRecipient, 86400],
        ];
        foreach ($limits as $limit => [$key, $max]) {
            if (RateLimiter::tooManyAttempts($key, $max)) {
                throw new ApplicationInvitationRefused('rate_limited', 429, 'Too many invitations. Try again later.', ['limit' => $limit],
                    ['Retry-After' => (string) max(1, RateLimiter::availableIn($key))]);
            }
        }
        foreach ($limits as [$key, , $decay]) {
            RateLimiter::hit($key, $decay);
        }
    }

    private function newToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
