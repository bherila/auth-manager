<?php

namespace App\Services\Invitations;

use App\Mail\InvitationCodeMail;
use App\Models\AccessInvitation;
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
 * and the account is created only in the same locked transaction that checks it.
 *
 * The package's sign-in code challenge cannot carry this: it belongs to an existing account, and here
 * there is none yet. This keeps that challenge's shape (six digits, a short expiry, a cap on wrong
 * entries, constant-time comparison) on the invitation row instead:
 *
 * - one live code per invitation, stored only as a keyed hash bound to the invitation, its current
 *   link and its address, so it is useless anywhere else and a resend (a new link) voids it;
 * - spent on success, on expiry, and after `max_attempts` wrong entries;
 * - at most `max_sends` per link, and `per_address_per_hour` to one address across invitations;
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
     * Email a new code for this invitation, replacing any earlier one.
     *
     * @return string `sent`, or why not: `mail_unavailable`, `rate_limited`, `send_limit`, `unavailable`
     *                (no longer pending, or the link was replaced), or `delivery_failed`
     */
    public function send(Request $request, AccessInvitation $invitation, string $tokenHash, string $applicationName): string
    {
        if (! AccessInvitationService::mailDelivers()) {
            return $this->refuseSend($request, $invitation, 'mail_unavailable');
        }
        $addressKey = 'invitation-code-address:'.hash('sha256', $invitation->email_normalized);
        if (RateLimiter::tooManyAttempts($addressKey, $this->setting('per_address_per_hour', 5))) {
            return $this->refuseSend($request, $invitation, 'rate_limited');
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        [$stored, $hash] = DB::transaction(function () use ($invitation, $tokenHash, $code): array {
            $locked = AccessInvitation::query()->lockForUpdate()->find($invitation->getKey());
            if (! $locked instanceof AccessInvitation || ! $locked->isPending() || ! hash_equals($locked->token_hash, $tokenHash)) {
                return ['unavailable', null];
            }
            if ($locked->verification_send_count >= $this->setting('max_sends', 5)) {
                return ['send_limit', null];
            }
            $hash = $this->hash($locked, $code);
            $locked->forceFill([
                'verification_code_hash' => $hash,
                'verification_expires_at' => now()->addMinutes($this->expiresMinutes()),
                'verification_attempts' => 0,
                'verification_send_count' => $locked->verification_send_count + 1,
            ])->save();

            return [self::SENT, $hash];
        });
        if ($stored !== self::SENT) {
            return $this->refuseSend($request, $invitation, $stored);
        }
        RateLimiter::hit($addressKey, 3600);

        try {
            Mail::to($invitation->email)->send(new InvitationCodeMail($applicationName, $code, $this->expiresMinutes()));
        } catch (Throwable $failure) {
            // Never the message or the transport's text: either could carry the code.
            Log::warning('An invitation code email could not be sent.', ['invitation_id' => $invitation->getKey(), 'exception' => $failure::class]);
            // Nobody received it, so nobody may use it.
            AccessInvitation::query()->whereKey($invitation->getKey())->where('verification_code_hash', $hash)
                ->update(['verification_code_hash' => null, 'verification_expires_at' => null]);

            return $this->refuseSend($request, $invitation, 'delivery_failed');
        }
        $this->audit->record(InvitationAudit::CODE_SENT, $invitation, $request, null, metadata: $this->metadata($invitation));

        return self::SENT;
    }

    /**
     * Check and spend the code, on an invitation row the caller has locked for the acceptance that
     * depends on it. Saves the attempt either way; the caller must commit it even when refusing.
     *
     * @return string `verified`, or why not: `missing` (none live), `expired`, `incorrect`, `exhausted`
     *                (this wrong entry was the last allowed)
     */
    public function consume(Request $request, AccessInvitation $locked, #[SensitiveParameter] ?string $code): string
    {
        $outcome = match (true) {
            $locked->verification_code_hash === null => 'missing',
            $locked->verification_expires_at === null || $locked->verification_expires_at->isPast() => 'expired',
            is_string($code) && preg_match('/^\d{6}$/D', $code) === 1
                && hash_equals($locked->verification_code_hash, $this->hash($locked, $code)) => self::VERIFIED,
            $locked->verification_attempts + 1 >= $this->setting('max_attempts', 5) => 'exhausted',
            default => 'incorrect',
        };

        $locked->forceFill(match ($outcome) {
            'incorrect' => ['verification_attempts' => $locked->verification_attempts + 1],
            'missing' => [],
            default => ['verification_code_hash' => null, 'verification_expires_at' => null, 'verification_attempts' => 0],
        })->save();

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
