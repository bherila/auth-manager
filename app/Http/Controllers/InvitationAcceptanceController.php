<?php

namespace App\Http\Controllers;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\AccessInvitation;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\Invitations\AccessInvitationService;
use App\Services\Invitations\InvitationRoles;
use App\Services\Invitations\InvitationUnavailable;
use App\Support\DelegatedAccessPermissions;
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
 */
class InvitationAcceptanceController extends Controller
{
    public function __construct(
        private readonly AccessInvitationService $invitations,
        private readonly InvitationRoles $roles,
        private readonly DelegatedAccessPermissions $permissions,
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
        ]);
    }

    public function accept(Request $request, #[SensitiveParameter] string $token): RedirectResponse|Response
    {
        $invitation = $this->pending($token);
        if ($invitation === null) {
            return $this->unavailable();
        }
        $state = $this->state($request, $invitation, $this->account($invitation));
        if (! in_array($state, ['accept', 'create'], true)) {
            return redirect()->route('invitations.show', ['token' => $token]);
        }

        $newAccount = $state === 'create' ? $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:12', 'max:72', static function (string $attribute, mixed $value, Closure $fail): void {
                if (is_string($value) && strlen($value) > 72) {
                    $fail('The password must use at most 72 UTF-8 bytes.');
                }
            }, 'confirmed'],
        ]) : null;

        try {
            [$person, $created] = $this->invitations->accept($request, $invitation, $state === 'accept' ? $request->user() : null,
                $newAccount === null ? null : ['name' => $newAccount['name'], 'password' => $newAccount['password']]);
        } catch (InvitationUnavailable) {
            return redirect()->route('invitations.show', ['token' => $token])
                ->with('invitation_error', 'The invitation could not be accepted as it was. Review it and try again.');
        }
        if ($created) {
            Auth::login($person);
            $request->session()->regenerate();
        }

        // After the acceptance has committed: the person is admitted whatever happens here.
        $roles = $this->roles->apply($invitation->fresh(), $person);
        $registration = RegisteredApplication::query()->where('key', $invitation->application)->first();

        return redirect()->route('invitations.accepted')->with('invitation_result', [
            'application' => $this->applicationName($invitation),
            'launch_url' => $registration?->launch_url,
            'roles_applied' => $roles === AccessInvitation::ROLES_APPLIED,
        ]);
    }

    public function accepted(Request $request): View|RedirectResponse
    {
        $result = $request->session()->get('invitation_result');
        if (! is_array($result)) {
            return redirect('/');
        }

        return view('invitations.accepted', ['result' => $result]);
    }

    /** Come back to the invitation after signing in. */
    public function signIn(Request $request, #[SensitiveParameter] string $token): RedirectResponse
    {
        $request->session()->put('url.intended', route('invitations.show', ['token' => $token]));

        return redirect()->route('login');
    }

    public function signOut(Request $request, #[SensitiveParameter] string $token): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('invitations.show', ['token' => $token]);
    }

    private function pending(#[SensitiveParameter] string $token): ?AccessInvitation
    {
        abort_unless($this->permissions->invitationsEnabled(), 404);

        return $this->invitations->findPending($token);
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
