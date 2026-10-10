<?php

namespace App\Services\DelegatedAccess;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Support\AuthManagerProfile;
use App\Support\DelegatedAccessApplications;
use App\Support\DelegatedAccessKeys;
use App\Support\DelegatedAccessPermissions;
use App\Support\StaticApplicationClients;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

final class DelegatedAccessTransport
{
    /**
     * A version 3 write whose answer was uncertain and whose receipt did not settle it: the
     * application has no stored outcome for it yet. It may still have happened.
     */
    public const STILL_UNKNOWN = 'outcome_still_unknown';

    public function __construct(private readonly ActorAssertion $assertions, private readonly DelegatedContract $contract, private readonly TransportClock $clock) {}

    /**
     * @param  array<string, mixed>|null  $capabilities  for a write: the validated capabilities the caller
     *                                                   checked it against. An answer that does not fit them
     *                                                   cannot confirm the write, so it is treated as uncertain
     *                                                   before the result is audited.
     */
    public function send(Request $request, string $application, array $operation, ?array $capabilities = null): array
    {
        return $this->dispatch($application, $operation, fn (bool $write): User => $this->actor($request, $application, $write), capabilities: $capabilities);
    }

    /**
     * Send as the inviter of an invitation being accepted, without the inviter's session.
     *
     * The one non-interactive path, and deliberately narrow: every operation, reads included, needs
     * the inviter to be active now, to hold `access-invite` and `access-manage` for the application,
     * a current grant to it, invitations switched on and writes enabled for it. The recent
     * confirmation an interactive write needs was required when the invitation was created; nothing
     * here reads a session, so it cannot be reached by presenting one. The application then decides
     * with its own rules, as it does for any actor.
     *
     * @param  int  $credentialVersion  the inviter's credential generation recorded with the invitation;
     *                                  a reset or revocation since then refuses
     * @param  string|null  $correlation  64 lowercase hex characters to identify an update by, so its
     *                                    caller can record it; generated when null
     * @param  array<string, mixed>|null  $capabilities  as for {@see send()}
     *
     * @throws DelegatedAccessException
     */
    public function sendForInvitation(User $inviter, int $credentialVersion, string $application, array $operation, ?string $correlation = null, ?array $capabilities = null): array
    {
        return $this->dispatch($application, $operation, fn (bool $write): User => $this->inviter($inviter, $credentialVersion, $application), $correlation, 'invitation', $capabilities);
    }

    private function dispatch(string $application, array $operation, Closure $resolveActor, ?string $correlation = null, ?string $via = null, ?array $capabilities = null): array
    {
        if (! config('delegated-access.enabled', false)) {
            throw new DelegatedAccessException('integration_disabled');
        }
        // A malformed application map refuses every call here, before anything is signed or sent.
        $entry = app(DelegatedAccessApplications::class)->find($application);
        $version = $entry['contract_version'] ?? DelegatedContract::VERSION_1;
        $payload = $this->contract->request($application, $operation, $version);
        $write = in_array($payload['operation'], DelegatedContract::WRITE_OPERATIONS, true);
        // A malformed key list is a configuration problem for reads and writes alike; resolved
        // first so a write is not refused as though the actor lacked permission.
        $signing = app(DelegatedAccessKeys::class)->for($application);
        $actor = $resolveActor($write);
        // The application's own key when it has one; the instance-wide key otherwise, which
        // writesEnabled() has already refused for a write.
        if ($write && ! $signing['own']) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        [$endpoint, $assertion, $body, $correlation] = $this->prepare($entry, $signing, $actor, $application, $payload, $correlation);

        if ($write) {
            $this->audit($actor, $payload, $correlation, 'attempt', $via);
        }
        try {
            $answer = $this->exchange($endpoint, $assertion, $body, $application, $payload, $write);
            // Checked before the result is audited: an answer that contradicts the capabilities it was
            // checked against confirms nothing, and is uncertain like a malformed one.
            if ($write && $capabilities !== null && ! $this->contract->fitsCapabilities($capabilities, $answer)) {
                throw new DelegatedAccessException('unknown_outcome');
            }
            $result = $answer;
        } catch (Throwable $failure) {
            $exception = $failure instanceof DelegatedAccessException ? $failure : new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
            if (! $write) {
                throw $exception;
            }
            // A version 3 write whose outcome is uncertain is looked up once by its operation id,
            // never sent again.
            $byReceipt = [];
            if ($exception->outcome === 'unknown_outcome' && $version === DelegatedContract::VERSION_3) {
                try {
                    $result = $this->checkReceipt($entry, $signing, $actor, $application, $payload, $correlation, $via, $capabilities);
                } catch (DelegatedAccessException $settled) {
                    $exception = $settled;
                    // A stored refusal settles the write as surely as a stored success does.
                    $byReceipt = $settled->outcome === self::STILL_UNKNOWN ? [] : ['confirmed_by' => 'receipt'];
                }
            }
            if (! isset($result)) {
                $this->audit($actor, $payload, $correlation, $exception->outcome, $via, $byReceipt);
                throw $exception;
            }
            $this->audit($actor, $payload, $correlation, 'succeeded', $via, ['confirmed_by' => 'receipt']);

            return $result;
        }
        if ($write) {
            $this->audit($actor, $payload, $correlation, 'succeeded', $via);
        }

        return $result;
    }

    /**
     * Whether a refusal leaves a write's outcome unknown: the application never confirmed it, and for
     * version 3 its receipt did not settle it either. Such a write may have happened.
     */
    public static function unconfirmed(DelegatedAccessException $exception): bool
    {
        return in_array($exception->outcome, ['unknown_outcome', self::STILL_UNKNOWN], true);
    }

    /**
     * Ask the application, once, what became of a version 3 write whose answer was uncertain.
     *
     * The receipt is a read: nothing is sent again, and it never reaches the adapter. A stored success
     * for this write is returned as its answer; a stored refusal is raised as that refusal; anything
     * else (no receipt yet, a pending claim, or a receipt request that itself failed) leaves the
     * outcome unknown. The check and what it found are audited before the caller sees either.
     *
     * @param  array{endpoint: string, contract_version: int}  $entry
     * @param  array<string, mixed>  $signing
     * @param  array<string, mixed>  $write  the write as the contract built it
     * @return array<string, mixed> the application's stored answer to the write
     *
     * @throws DelegatedAccessException the stored refusal, or {@see STILL_UNKNOWN}
     */
    private function checkReceipt(array $entry, array $signing, User $actor, string $application, array $write, string $writeCorrelation, ?string $via, ?array $capabilities): array
    {
        $found = 'unknown';
        $refusal = null;
        $answer = null;
        try {
            $ask = $this->contract->request($application, ['operation' => 'receipt', 'operation_id' => $write['operation_id']], DelegatedContract::VERSION_3);
            [$endpoint, $assertion, $body] = $this->prepare($entry, $signing, $actor, $application, $ask, null);
            $receipt = $this->contract->receipt($this->exchange($endpoint, $assertion, $body, $application, $ask, false), $application, $write);
            if ($receipt['status'] === 'known' && $receipt['response_status'] === 200) {
                // A stored answer that does not fit the capabilities settles nothing either.
                if ($capabilities !== null && ! $this->contract->fitsCapabilities($capabilities, $receipt['response'])) {
                    throw new DelegatedAccessException('invalid_response');
                }
                $found = 'applied';
                $answer = $receipt['response'];
            } elseif ($receipt['status'] === 'known') {
                $found = 'refused';
                $refusal = ['status' => $receipt['response_status'], 'error' => $receipt['response']['error']];
            }
        } catch (Throwable) {
            // The receipt request failed or was malformed: it settles nothing.
        }

        try {
            $this->record($actor, 'delegated_access_receipt_check', $found !== 'unknown', [
                ...$this->auditSubject($actor, $write), 'outcome' => $found, 'correlation' => $writeCorrelation,
                'operation_id' => $write['operation_id'],
                ...($refusal === null ? [] : ['refusal' => $refusal['error'], 'refusal_status' => $refusal['status']]),
                ...($via === null ? [] : ['via' => $via]),
            ]);
        } catch (Throwable) {
            throw new DelegatedAccessException(self::STILL_UNKNOWN);
        }

        if ($answer !== null) {
            return $answer;
        }
        if ($refusal !== null) {
            // Acted on by its status, as an immediate refusal would have been.
            throw new DelegatedAccessException(match ($refusal['status']) {
                403, 404 => 'not_authorized',
                409 => 'revision_conflict',
                default => 'invalid_request',
            }, $refusal['status']);
        }

        throw new DelegatedAccessException(self::STILL_UNKNOWN);
    }

    /**
     * The endpoint, a signed assertion over the exact body, the body and its correlation.
     *
     * @param  array{endpoint: string, contract_version: int}|null  $entry
     * @param  array<string, mixed>  $signing
     * @param  array<string, mixed>  $payload
     * @return array{0: string, 1: string, 2: string, 3: string}
     *
     * @throws DelegatedAccessException
     */
    private function prepare(?array $entry, array $signing, User $actor, string $application, array $payload, ?string $correlation): array
    {
        $endpoint = $entry['endpoint'] ?? null;
        $issuer = config('delegated-access.issuer');
        $keyPath = $signing['private_key_path'];
        $keyId = $signing['key_id'];
        try {
            AuthManagerProfile::validatedAbsoluteUrl($endpoint, 'Delegated endpoint');
            $issuer = AuthManagerProfile::validatedIssuerUrl($issuer, 'Delegated issuer');
            if (parse_url($endpoint, PHP_URL_SCHEME) !== 'https' || parse_url($issuer, PHP_URL_SCHEME) !== 'https'
                || ! is_string($keyPath) || ! is_readable($keyPath) || ! is_string($keyId) || $keyId === '') {
                throw new DelegatedAccessException('invalid_configuration');
            }
            $body = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (strlen($body) > DelegatedContract::MAX_REQUEST_BYTES) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
            $key = file_get_contents($keyPath);
            if (! is_string($key) || $key === '') {
                throw new DelegatedAccessException('invalid_configuration');
            }
            $correlation ??= bin2hex(random_bytes(32));
            $assertion = $this->assertions->issue($issuer, (string) $actor->id, $endpoint, $application, $body, $keyId, $key, $correlation);
        } catch (DelegatedAccessException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new DelegatedAccessException('invalid_configuration');
        }

        return [$endpoint, $assertion, $body, $correlation];
    }

    /**
     * Refuse, before anything is sent, unless this actor could write to the application now.
     *
     * The same checks a write makes before signing: manage permission, a current grant, writes
     * enabled for the application and a recent confirmation. None depends on the target, so a
     * caller that must answer identically for every target makes them first.
     *
     * @throws DelegatedAccessException
     */
    public function authorizeWrite(Request $request, string $application): void
    {
        app(DelegatedAccessKeys::class)->for($application);
        $this->actor($request, $application, true);
    }

    /**
     * The contract version agreed with this application, from deployment configuration.
     *
     * Never negotiated at runtime and never taken from a response: an application that could
     * choose the version could choose which rules its answers are checked against. An unknown
     * value makes the whole map malformed, which refuses the call with `invalid_configuration`.
     *
     * @throws DelegatedAccessException when the application map is malformed
     */
    public static function contractVersion(string $application): int
    {
        return app(DelegatedAccessApplications::class)->contractVersion($application);
    }

    /**
     * @param  array<string, mixed>  $payload  the write as the contract built it
     * @param  array<string, mixed>  $extra
     */
    private function audit(User $actor, array $payload, string $correlation, string $outcome, ?string $via = null, array $extra = []): void
    {
        try {
            $this->record($actor, $outcome === 'attempt' ? 'delegated_access_update_attempt' : 'delegated_access_update_result', $outcome === 'succeeded', [
                ...$this->auditSubject($actor, $payload), 'outcome' => $outcome, 'correlation' => $correlation,
                ...(isset($payload['operation_id']) ? ['operation_id' => $payload['operation_id']] : []),
                ...$extra, ...($via === null ? [] : ['via' => $via]),
            ]);
        } catch (Throwable) {
            // A missing attempt record prevents transmission. A failed result record
            // leaves a durable attempt and must never turn a remote write into success.
            throw new DelegatedAccessException($outcome === 'attempt' ? 'audit_unavailable' : 'unknown_outcome');
        }
    }

    /**
     * Who acted on what. Every write audit, the receipt check's included, starts with these, so one
     * query finds a write's whole trail by its correlation or operation id.
     *
     * @param  array<string, mixed>  $payload
     * @return array<string, string>
     */
    private function auditSubject(User $actor, array $payload): array
    {
        return ['actor' => (string) $actor->id, 'application' => $payload['application'], 'target' => $payload['subject'], 'operation' => $payload['operation']];
    }

    /**
     * Append one audit record, committed on its own: never inside a caller's transaction, whose
     * rollback could erase it after the application acted.
     *
     * @param  array<string, mixed>  $metadata
     *
     * @throws DelegatedAccessException when it cannot be recorded
     */
    private function record(User $actor, string $event, bool $succeeded, array $metadata): void
    {
        if ((new AuthAuditLog)->getConnection()->transactionLevel() !== 0) {
            throw new DelegatedAccessException('audit_unavailable');
        }
        $entry = AuthAuditLog::create([
            'user_id' => $actor->id, 'acting_user_id' => $actor->id, 'event' => $event,
            'auth_method' => 'delegated', 'succeeded' => $succeeded, 'metadata' => $metadata,
        ]);
        if (! $entry->exists) {
            throw new DelegatedAccessException('audit_unavailable');
        }
    }

    /**
     * Guzzle options that bound the response under either of its handlers.
     *
     * The stream handler (selected when allow_url_fopen is on) streams lazily, so the bounded read
     * in exchange() applies. Curl buffers the body first, so a declared oversize body is refused
     * from its headers, and the progress callback aborts a transfer the moment it passes the bound,
     * declared or not. No handler-specific option is sent: current Guzzle refuses
     * CURLOPT_MAXFILESIZE in `curl`, which failed every exchange on hosts without allow_url_fopen
     * before it reached the network.
     *
     * @return array<string, mixed>
     */
    public static function requestOptions(): array
    {
        return [
            'stream' => true,
            'read_timeout' => 1,
            'on_headers' => static function (ResponseInterface $headers): void {
                $declared = $headers->getHeaderLine('Content-Length');
                if ($declared !== '' && (! ctype_digit($declared) || (int) $declared > DelegatedContract::MAX_RESPONSE_BYTES)) {
                    throw new RuntimeException('The application response exceeds the contract size limit.');
                }
            },
            'progress' => static function (int|float $expected, int|float $received): void {
                if ($expected > DelegatedContract::MAX_RESPONSE_BYTES || $received > DelegatedContract::MAX_RESPONSE_BYTES) {
                    throw new RuntimeException('The application response exceeds the contract size limit.');
                }
            },
        ];
    }

    private function exchange(string $endpoint, #[\SensitiveParameter] string $assertion, string $body, string $application, array $payload, bool $write): array
    {
        $deadline = $this->clock->now() + 10;
        try {
            // Never retry writes or follow redirects. Read at most the contract bound.
            $response = Http::connectTimeout(3)->timeout(10)->withoutRedirecting()
                ->withOptions(self::requestOptions())
                ->withHeaders(['Authorization' => 'Bearer '.$assertion, 'Accept' => 'application/json'])
                ->withBody($body, 'application/json')->post($endpoint);
        } catch (Throwable) {
            throw new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
        }
        $stream = $response->toPsrResponse()->getBody();
        try {
            if ($this->clock->now() >= $deadline) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'invalid_response');
            }
            if (in_array($response->status(), [403, 404, 409, 422], true)) {
                throw new DelegatedAccessException(match ($response->status()) {
                    403, 404 => 'not_authorized',
                    409 => 'revision_conflict',
                    422 => 'invalid_request',
                }, $response->status());
            }
            if (! $response->successful()) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'unavailable');
            }
            try {
                $bytes = '';
                while (! $stream->eof() && strlen($bytes) <= DelegatedContract::MAX_RESPONSE_BYTES) {
                    if ($this->clock->now() >= $deadline) {
                        throw new DelegatedAccessException('invalid_response');
                    }
                    $chunk = $stream->read(min(8192, DelegatedContract::MAX_RESPONSE_BYTES + 1 - strlen($bytes)));
                    if ($this->clock->now() >= $deadline || ($chunk === '' && ! $stream->eof())) {
                        throw new DelegatedAccessException('invalid_response');
                    }
                    $bytes .= $chunk;
                }
                if ($this->clock->now() >= $deadline || strlen($bytes) > DelegatedContract::MAX_RESPONSE_BYTES) {
                    throw new DelegatedAccessException('invalid_response');
                }

                return $this->contract->response(json_decode($bytes, true, 64, JSON_THROW_ON_ERROR), $application, $payload['operation'], $payload['subject'] ?? null, $payload['contract_version']);
            } catch (Throwable) {
                throw new DelegatedAccessException($write ? 'unknown_outcome' : 'invalid_response');
            }
        } finally {
            $stream->close();
        }
    }

    private function actor(Request $request, string $application, bool $write): User
    {
        $sessionUser = $request->user();
        $actor = $sessionUser instanceof User ? User::query()->find($sessionUser->id) : null;
        if (! $actor instanceof User || ! $actor->canLogin() || ! $request->hasSession()
            || $request->session()->get(EnsureCredentialVersion::SESSION_KEY) !== (int) $actor->credential_version) {
            throw new DelegatedAccessException('not_authenticated', 401);
        }
        // The provider's own restriction, before anything is signed: viewing needs
        // access-view (or manage) for this application, writing needs
        // access-manage and writes switched on for this application.
        $permissions = app(DelegatedAccessPermissions::class);
        if (! ($write ? $permissions->canManage($actor, $application) : $permissions->canView($actor, $application))) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        $this->assertGranted($actor, $application);
        if ($write) {
            // Writes switched off for this application are a refusal, not a request to re-confirm.
            if (! $permissions->writesEnabled($application)) {
                throw new DelegatedAccessException('not_authorized', 403);
            }
            $proof = $request->session()->get(RequireRecentPasskeyAuthentication::SESSION_KEY);
            $now = now()->getTimestamp();
            if (! is_array($proof)
                || ($proof['user_id'] ?? null) !== (string) $actor->id
                || ! is_int($proof['authenticated_at'] ?? null)
                || $proof['authenticated_at'] > $now || $proof['authenticated_at'] < $now - 300) {
                throw new DelegatedAccessException('recent_confirmation_required', 403);
            }
        }

        return $actor;
    }

    /** The inviter, re-checked now: {@see sendForInvitation()}. */
    private function inviter(User $inviter, int $credentialVersion, string $application): User
    {
        $actor = User::query()->find($inviter->getKey());
        if (! $actor instanceof User || ! $actor->canLogin() || (int) $actor->credential_version !== $credentialVersion) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        $permissions = app(DelegatedAccessPermissions::class);
        if (! $permissions->invitationsEnabled() || ! $permissions->canInvite($actor, $application)
            || ! $permissions->writesEnabled($application)) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        $this->assertGranted($actor, $application);

        return $actor;
    }

    /** The actor holds a current grant to an eligible client of the enabled registration. */
    private function assertGranted(User $actor, string $application): void
    {
        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->with('clients')->first();
        $staticClients = new StaticApplicationClients;
        if ($registration === null || ! $registration->clients->contains(fn (PassportClient $client): bool => $staticClients->eligible($client)
            && DB::table('oauth_client_grants')->where('subject', $actor->id)->where('oauth_client_id', $client->id)->exists())) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
    }
}
