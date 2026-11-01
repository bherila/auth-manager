<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Models\AccessInvitation;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\Invitations\AccessInvitationService;
use BWH\AuthManager\Services\Invitations\InvitationAddressVerification;
use BWH\AuthManager\Services\Invitations\InvitationCodeRejected;
use BWH\AuthManager\Services\Invitations\InvitationRoles;
use BWH\AuthManager\Services\Invitations\InvitationUnavailable;
use BWH\AuthManager\Support\ApplicationInvitations;
use BWH\AuthManager\Support\DelegatedAccessPermissions;
use Closure;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use SensitiveParameter;

/**
 * The page an invitation link opens, for its recipient.
 *
 * If an account has the invited address (case-insensitively) the recipient signs in as that account
 * and accepts; someone signed in as anyone else is refused and offered a sign-out. Otherwise they
 * create the account, with the address fixed to the invited one. A disabled or deleted account
 * cannot accept. Every unusable link (unknown, used, revoked or expired) gets one answer.
 *
 * An application's own invitation creates an account only with a code first emailed to the invited
 * address ({@see InvitationAddressVerification}): its link was returned to the application, so
 * opening it proves nothing. Accepting for an existing account is unchanged.
 */
class InvitationAcceptanceController extends Controller
{
    public function __construct(
        private readonly AccessInvitationService $invitations,
        private readonly InvitationRoles $roles,
        private readonly DelegatedAccessPermissions $permissions,
        private readonly ApplicationInvitations $applicationInvitations,
        private readonly InvitationAddressVerification $verification,
    ) {}

    public function show(Request $request, #[SensitiveParameter] string $token): View|Response
    {
        $invitation = $this->pending($token);
        if ($invitation === null) {
            return $this->unavailable();
        }

        return view('invitations.show', [
            'token' => $token, 'invitation' => $invitation,
            'applicationName' => $this->applicationName($invitation),
            'state' => $this->state($request, $invitation, $this->account($invitation)),
            'needsCode' => $invitation->requestedByApplication(),
            'codeLive' => $invitation->verificationCodeLive(),
            'codeMinutes' => $this->verification->expiresMinutes(),
        ]);
    }

    /**
     * Email a code to the invited address, before creating an account from an application's own
     * invitation. Anything else (an existing account, someone signed in, the provider's own
     * invitations) goes back to the page, as accepting does.
     */
    public function sendCode(Request $request, #[SensitiveParameter] string $token): RedirectResponse|Response
    {
        $invitation = $this->pending($token);
        if ($invitation === null) {
            return $this->unavailable();
        }
        $back = redirect()->route('auth-manager.invitations.show', ['token' => $token]);
        if (! $invitation->requestedByApplication() || $this->state($request, $invitation, $this->account($invitation)) !== 'create') {
            return $back;
        }

        $outcome = $this->verification->send($request, $invitation, AccessInvitation::hashToken($token), $this->applicationName($invitation));

        return match ($outcome) {
            InvitationAddressVerification::SENT => $back->with('invitation_code_sent', true),
            'mail_unavailable', 'delivery_failed' => $back->with('invitation_error', 'The code could not be sent, so the account cannot be created right now. Try again later, or contact the person who invited you.'),
            'rate_limited', 'send_limit' => $back->with('invitation_error', 'Too many codes have been sent for this invitation. Try again later, or ask the person who invited you to send it again.'),
            default => $back->with('invitation_error', 'The invitation could not be accepted as it was. Review it and try again.'),
        };
    }

    public function accept(Request $request, #[SensitiveParameter] string $token): RedirectResponse|Response
    {
        $invitation = $this->pending($token);
        if ($invitation === null) {
            return $this->unavailable();
        }
        $state = $this->state($request, $invitation, $this->account($invitation));
        if (! in_array($state, ['accept', 'create'], true)) {
            return redirect()->route('auth-manager.invitations.show', ['token' => $token]);
        }

        $newAccount = $state === 'create' ? $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:12', 'max:72', static function (string $attribute, mixed $value, Closure $fail): void {
                if (is_string($value) && strlen($value) > 72) {
                    $fail('The password must use at most 72 UTF-8 bytes.');
                }
            }, 'confirmed'],
            // Any string: a malformed code is a wrong one, and counts as an attempt.
            ...($invitation->requestedByApplication() ? ['code' => ['required', 'string', 'max:32']] : []),
        ]) : null;

        try {
            [$person, $created] = $this->invitations->accept($request, $invitation, AccessInvitation::hashToken($token), $state === 'accept' ? $request->user() : null,
                $newAccount === null ? null : ['name' => $newAccount['name'], 'password' => $newAccount['password'], 'code' => $newAccount['code'] ?? null]);
        } catch (InvitationCodeRejected $rejected) {
            return redirect()->route('auth-manager.invitations.show', ['token' => $token])->withInput($request->only('name'))->withErrors(['code' => match ($rejected->reason) {
                'incorrect' => 'That code is not right. Check the most recent email and try again.',
                'expired' => 'That code has expired. Send a new one.',
                'exhausted' => 'Too many incorrect codes. Send a new one.',
                default => 'Send a code to your email address first, then enter it here.',
            }]);
        } catch (InvitationUnavailable) {
            return redirect()->route('auth-manager.invitations.show', ['token' => $token])
                ->with('invitation_error', 'The invitation could not be accepted as it was. Review it and try again.');
        }
        if ($created) {
            Auth::login($person);
            $request->session()->regenerate();
        }

        // After the acceptance has committed: the person is admitted whatever happens here. An
        // application's own invitation carries no roles; the application sets up its access.
        $roles = $invitation->requestedByApplication() ? AccessInvitation::ROLES_APPLIED : $this->roles->apply($invitation->fresh(), $person);
        $registration = RegisteredApplication::query()->where('key', $invitation->application)->first();

        return redirect()->route('auth-manager.invitations.accepted')->with('invitation_result', [
            'application' => $this->applicationName($invitation),
            'launch_url' => $registration?->launch_url,
            'roles_applied' => $roles === AccessInvitation::ROLES_APPLIED,
        ]);
    }

    public function accepted(Request $request): View|RedirectResponse
    {
        $result = $request->session()->get('invitation_result');
        if (! is_array($result)) {
            return redirect()->route('auth-manager.home');
        }

        return view('invitations.accepted', ['result' => $result]);
    }

    /** Come back to the invitation after signing in. */
    public function signIn(Request $request, #[SensitiveParameter] string $token): RedirectResponse
    {
        $request->session()->put('url.intended', route('auth-manager.invitations.show', ['token' => $token]));

        return redirect()->route('auth-manager.login');
    }

    public function signOut(Request $request, #[SensitiveParameter] string $token): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('auth-manager.invitations.show', ['token' => $token]);
    }

    /**
     * The pending invitation, while its own path is switched on: the provider's invitations for one
     * sent from its pages; for one an application requested, that application still listed and its
     * requesting client still one of its sign-in clients. One answer otherwise.
     */
    private function pending(#[SensitiveParameter] string $token): ?AccessInvitation
    {
        abort_unless($this->permissions->invitationsEnabled() || $this->applicationInvitations->anyEnabled(), 404);
        $invitation = $this->invitations->findPending($token);
        if (! $invitation instanceof AccessInvitation) {
            return null;
        }

        return ($invitation->requestedByApplication()
            ? $this->applicationInvitations->admittingClient($invitation) !== null
            : $this->permissions->invitationsEnabled()) ? $invitation : null;
    }

    /** The invited address's account, null for none, or false when several match it. */
    private function account(AccessInvitation $invitation): User|false|null
    {
        try {
            return $this->invitations->accountFor($invitation);
        } catch (InvitationUnavailable) {
            return false;
        }
    }

    /**
     * ambiguous: more than one account has the invited address, so none can accept;
     * disabled: the invited address belongs to an account that cannot sign in;
     * wrong_account: signed in as anyone but the invited account;
     * accept: signed in as the invited account; sign_in: it exists, nobody is signed in;
     * create: no account has the address and nobody is signed in.
     */
    private function state(Request $request, AccessInvitation $invitation, User|false|null $account): string
    {
        if ($account === false) {
            return 'ambiguous';
        }
        $user = $request->user();
        $current = $user instanceof User && $request->hasSession()
            && $request->session()->get(EnsureCredentialVersion::SESSION_KEY) === (int) $user->credential_version;

        return match (true) {
            $account !== null && ! $account->canLogin() => 'disabled',
            $user !== null && ($account === null || $account->getKey() !== $user->getKey()) => 'wrong_account',
            $user !== null && $current => 'accept',
            $user !== null => 'sign_in',
            $account !== null => 'sign_in',
            default => 'create',
        };
    }

    private function applicationName(AccessInvitation $invitation): string
    {
        return (string) (RegisteredApplication::query()->where('key', $invitation->application)->value('name') ?? $invitation->application);
    }

    private function unavailable(): Response
    {
        return response()->view('invitations.unavailable', [], 404);
    }
}
