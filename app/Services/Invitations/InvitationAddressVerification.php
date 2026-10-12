<?php

namespace App\Services\Invitations;

use App\Mail\InvitationCodeMail;
use App\Models\AccessInvitation;
use App\Models\InvitationAcceptanceCode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\RateLimiter;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * Proof of the invited address before an application's own invitation creates an account.
 *
 * Its link is returned to the application every time, so whoever opens it may not read the address.
 * Before acceptance creates an account, the provider emails a six-digit code to the invited address,
 * and the account is created only in the same locked transaction that checks and spends it.
 *
 * The package's sign-in code challenge cannot carry this: it belongs to an existing account, and here
 * there is none yet. This keeps that challenge's shape (six digits, a short expiry, a cap on wrong
 * entries, constant-time comparison), with a row per code ({@see InvitationAcceptanceCode}):
 *
 * - each code is stored only as a keyed hash bound to the invitation, its current link and its
 *   address, so it is useless anywhere else, and a resend (a new link) deletes them all;
 * - every delivered, unexpired, unused code for the invitation works, so a second send never voids a
 *   code already in the person's inbox; one is spent on success (and the rest with it), all expire;
 * - wrong entries count per invitation, and `max_attempts` of them burn every live code; at most
 *   `max_sends` codes per link and `per_address_per_hour` to one address across invitations, so
 *   one link allows at most `max_sends` x `max_attempts` wrong entries;
 * - the email is sent only after its row has committed, never inside a transaction or under a lock;
 *   a failed send deletes its row and counts against neither limit;
 * - none at all when the provider's mailer does not deliver: the account then cannot be created.
 *
 * Audit rows name the invitation and the outcome, never the address or the code.
 */
final class InvitationAddressVerification
{
    public const SENT = 'sent';

    public const VERIFIED = 'verified';

    public function __construct(private readonly InvitationAudit $audit) {}

    /**
     * Email a new code for this invitation. Earlier codes stay usable until they expire.
     *
     * @return string `sent`, or why not: `mail_unavailable`, `rate_limited`, `send_limit`, `unavailable`
     *                (no longer pending, or the link was replaced), or `delivery_failed`
     */
    public function send(Request $request, AccessInvitation $invitation, string $tokenHash, string $applicationName): string
    {
        if (! AccessInvitationService::mailDelivers()) {
            return $this->refuseSend($request, $invitation, 'mail_unavailable');
        }
        // Count first and decide on the count this request took, so concurrent requests for other
        // invitations to the same address cannot all pass a check made before any of them counted.
        // Anything not delivered gives its count back.
        $addressKey = 'invitation-code-address:'.InvitationAcceptanceCode::addressHash($invitation->email_normalized);
        if (RateLimiter::hit($addressKey, 3600) > $this->setting('per_address_per_hour', 5)) {
            return $this->refuseSend($request, $invitation, 'rate_limited');
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        // Reserve the link's send and store the code, briefly locked; the email goes after this commits.
        $row = DB::transaction(function () use ($invitation, $tokenHash, $code): InvitationAcceptanceCode|string {
            $locked = AccessInvitation::query()->lockForUpdate()->find($invitation->getKey());
            if (! $locked instanceof AccessInvitation || ! $locked->isPending() || ! hash_equals($locked->token_hash, $tokenHash)) {
                return 'unavailable';
            }
            if ($locked->verification_send_count >= $this->setting('max_sends', 5)) {
                return 'send_limit';
            }
            $locked->forceFill(['verification_send_count' => $locked->verification_send_count + 1])->save();

            return $locked->acceptanceCodes()->create([
                'address_hash' => InvitationAcceptanceCode::addressHash($locked->email_normalized),
                'code_hash' => $this->hash($locked, $code),
                'expires_at' => now()->addMinutes($this->expiresMinutes()),
                'created_at' => now(),
            ]);
        });
        if (is_string($row)) {
            RateLimiter::decrement($addressKey, 3600);

            return $this->refuseSend($request, $invitation, $row);
        }

        try {
            Mail::to($invitation->email)->send(new InvitationCodeMail($applicationName, $code, $this->expiresMinutes()));
        } catch (Throwable $failure) {
            // Never the message or the transport's text: either could carry the code.
            Log::warning('An invitation code email could not be sent.', ['invitation_id' => $invitation->getKey(), 'exception' => $failure::class]);
            // Nobody received it: it may not be used, and it counts against neither limit. Codes that
            // were delivered earlier are untouched.
            $row->delete();
            RateLimiter::decrement($addressKey, 3600);
            // Only while the link that reserved the send is still current: after a resend, the counter
            // belongs to the new link, and this failure owes it nothing.
            AccessInvitation::query()->whereKey($invitation->getKey())->where('token_hash', $tokenHash)
                ->where('verification_send_count', '>', 0)->decrement('verification_send_count');

            return $this->refuseSend($request, $invitation, 'delivery_failed');
        }
        $this->audit->record(InvitationAudit::CODE_SENT, $invitation, $request, null, metadata: $this->metadata($invitation));

        return self::SENT;
    }

    /**
     * Check and spend a code, on an invitation row the caller has locked for the acceptance that
     * depends on it. Saves the attempt either way; the caller must commit it even when refusing.
     *
     * @return string `verified`, or why not: `missing` (none live), `expired`, `incorrect`, `exhausted`
     *                (this wrong entry was the last allowed, and every live code is now spent)
     */
    public function consume(Request $request, AccessInvitation $locked, #[SensitiveParameter] ?string $code): string
    {
        $codes = $locked->acceptanceCodes()->whereNull('consumed_at')
            ->where('address_hash', InvitationAcceptanceCode::addressHash($locked->email_normalized))
            ->lockForUpdate()->get();
        $live = $codes->filter(fn (InvitationAcceptanceCode $row): bool => $row->expires_at->isFuture());

        if ($live->isEmpty()) {
            $outcome = $codes->isEmpty() ? 'missing' : 'expired';
        } else {
            $hash = is_string($code) && preg_match('/^\d{6}$/D', $code) === 1 ? $this->hash($locked, $code) : null;
            // Every live code is compared, in constant time, whichever matches.
            $match = null;
            foreach ($live as $row) {
                if ($hash !== null && hash_equals($row->code_hash, $hash)) {
                    $match = $row;
                }
            }
            $outcome = match (true) {
                // Spent only if nobody spent it first.
                $match !== null => InvitationAcceptanceCode::query()->whereKey($match->getKey())->whereNull('consumed_at')
                    ->update(['consumed_at' => now()]) === 1 ? self::VERIFIED : 'missing',
                $locked->verification_attempts + 1 >= $this->setting('max_attempts', 5) => 'exhausted',
                default => 'incorrect',
            };
        }

        if ($outcome === 'incorrect') {
            $locked->forceFill(['verification_attempts' => $locked->verification_attempts + 1])->save();
        } elseif (in_array($outcome, [self::VERIFIED, 'exhausted'], true)) {
            // Success needs no other code; the last wrong entry allowed burns them all.
            $locked->acceptanceCodes()->whereNull('consumed_at')->update(['consumed_at' => now()]);
            $locked->forceFill(['verification_attempts' => 0])->save();
        }

        if ($outcome !== self::VERIFIED) {
            $this->audit->record(InvitationAudit::CODE_REJECTED, $locked, $request, null, succeeded: false,
                metadata: [...$this->metadata($locked), 'reason' => $outcome]);
        }

        return $outcome;
    }

    public function expiresMinutes(): int
    {
        return $this->setting('expires_minutes', 15);
    }

    private function refuseSend(Request $request, AccessInvitation $invitation, string $reason): string
    {
        $this->audit->record(InvitationAudit::CODE_SENT, $invitation, $request, null, succeeded: false,
            metadata: [...$this->metadata($invitation), 'reason' => $reason]);

        return $reason;
    }

    /**
     * Keyed with the application key, so a copy of the table does not give the codes away, and bound
     * to this invitation, its current link and its address.
     */
    private function hash(AccessInvitation $invitation, #[SensitiveParameter] string $code): string
    {
        $key = (string) config('app.key');
        if ($key === '') {
            throw new RuntimeException('The application key is not set; invitation codes cannot be issued or checked.');
        }

        return hash_hmac('sha256', implode("\0", ['invitation-code', (string) $invitation->getKey(), $invitation->token_hash, $invitation->email_normalized, $code]), $key);
    }

    /** @return array<string, mixed> */
    private function metadata(AccessInvitation $invitation): array
    {
        return ['via' => 'application', 'oauth_client_id' => $invitation->requesting_client_id];
    }

    private function setting(string $name, int $default): int
    {
        return max(1, (int) config("application-invitations.verification.{$name}", $default));
    }
}
