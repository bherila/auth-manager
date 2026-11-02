<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Mail\PasswordResetNoticeMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthTokenRevocationService;
use BWH\AuthManager\Support\Mount;
use Closure;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\PasswordResetLinkSent;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;
use Illuminate\Validation\Rules\Password as PasswordRule;
use Illuminate\View\View;
use Throwable;

/**
 * Self-service password reset, on an instance that enables it.
 *
 * Provider-owned rather than auth-laravel's PasswordResetController, which signs the person
 * in, leaves earlier sessions and OAuth credentials live, and ignores the instance's minimum
 * password length. It goes through the same broker and sends the same mail.
 */
final class PasswordResetController
{
    private const LINK_SENT = 'If an account exists with this email, a password reset link has been sent.';

    private const INVALID_LINK = 'This password reset link is invalid or has expired. Request a new one.';

    /** Long enough to cover sending the mail, so a known address takes no longer to answer. */
    private const REQUEST_MINIMUM_MICROSECONDS = 1_500_000;

    public function __construct(
        private readonly AuthAuditLogger $audit,
        private readonly LocalCredentialPolicy $localCredentials,
        private readonly OAuthTokenRevocationService $tokens,
    ) {}

    public function request(): View
    {
        $this->ensureEnabled();

        return view('password.forgot');
    }

    public function email(Request $request, Timebox $timebox): RedirectResponse
    {
        $this->ensureEnabled();

        $validated = $request->validate(['email' => ['required', 'email', 'max:254']]);

        $timebox->call(function () use ($request, $validated): void {
            $this->broker()->sendResetLink(['email' => trim($validated['email'])], function (User $user, string $token) use ($request): void {
                // Nothing goes to an account that may not hold a local password.
                if (! $this->localCredentials->mayUseLocalCredentials($user, $request)) {
                    return;
                }

                $url = strtr((string) config('bherila-auth.password_resets.reset_url'), [
                    '{token}' => rawurlencode($token),
                    '{email}' => rawurlencode($user->email),
                ]);

                // A failed send must look like every other answer.
                $this->sendQuietly($user, new PasswordResetConfirmationMail($user, $url, (string) config('app.name')));
                $this->audit->passwordResetRequested($request, $user);
                event(new PasswordResetLinkSent($user));
            });
        }, self::REQUEST_MINIMUM_MICROSECONDS);

        // The same answer for a sent link, an unknown address and a throttled request.
        return back()->with('status', self::LINK_SENT);
    }

    public function edit(Request $request, string $token): View
    {
        $this->ensureEnabled();

        return view('password.reset', ['token' => $token, 'email' => (string) $request->query('email', '')]);
    }

    public function update(Request $request): RedirectResponse
    {
        $this->ensureEnabled();

        $validated = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['required', 'email', 'max:254'],
            'password' => ['required', 'confirmed', 'max:72', PasswordRule::min((int) config('auth-manager.password_min_length')), static function (string $attribute, mixed $value, Closure $fail): void {
                // bcrypt reads only the first 72 bytes, so a longer password is refused rather than cut short.
                if (is_string($value) && strlen($value) > 72) {
                    $fail('The password must use at most 72 UTF-8 bytes.');
                }
            }],
        ]);

        $resetUser = null;
        $status = DB::transaction(function () use ($request, $validated, &$resetUser): string {
            return $this->broker()->reset([
                'email' => trim($validated['email']),
                'token' => $validated['token'],
                'password' => $validated['password'],
            ], function (User $user, string $password) use ($request, &$resetUser): void {
                // Rechecked under the lock: the token may predate the account becoming ineligible.
                // A disabled account may still take its password back; signing in stays refused.
                $locked = User::query()->lockForUpdate()->findOrFail($user->getKey());
                if (! $this->localCredentials->mayUseLocalCredentials($locked, $request)) {
                    return;
                }

                $locked->forceFill([
                    'password' => $password,
                    'credential_version' => (int) $locked->credential_version + 1,
                    'remember_token' => Str::random(60),
                ])->save();
                $this->tokens->forSubject((string) $locked->getKey());
                DB::table('sessions')->where('user_id', $locked->getKey())->delete();
                // A code requested with the old password must not finish a sign-in now.
                TwoFactorAttempt::query()->where('user_id', $locked->getKey())->delete();
                $this->audit->passwordResetCompleted($request, $locked);

                $resetUser = $locked;
            });
        });

        if ($status !== Password::PASSWORD_RESET || ! $resetUser instanceof User) {
            return back()
                ->withErrors(['email' => self::INVALID_LINK])
                ->withInput($request->only('email'));
        }

        $this->sendQuietly($resetUser, new PasswordResetNoticeMail($resetUser, (string) config('app.name')));
        event(new PasswordReset($resetUser));

        // This browser may hold a session too, and saving it would write the row back.
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('auth-manager.login')
            ->with('status', 'Your password has been reset. Sign in with your new password.');
    }

    private function broker(): PasswordBroker
    {
        return Password::broker(Mount::embedded() ? Mount::EMBEDDED_USER_PROVIDER : null);
    }

    private function ensureEnabled(): void
    {
        // Before any lookup, so the answer is the same for every address.
        abort_unless(config('auth-manager.sign_in.password_reset'), 404);
    }

    private function sendQuietly(User $user, object $mail): void
    {
        try {
            Mail::to($user->email)->send($mail);
        } catch (Throwable $exception) {
            report($exception);
        }
    }
}
