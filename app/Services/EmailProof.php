<?php

namespace BWH\AuthManager\Services;

use BWH\AuthManager\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * Records that a person proved they receive mail at their account's current address, and
 * forgets proof that no longer applies.
 *
 * Proof is bound to the address it was made for. A secret mailed to an address proves only
 * that address: a code or reset link sent before an administrator changed the address must
 * neither finish nor prove the new one, so {@see self::forgetAddress()} withdraws them, and
 * {@see self::proveCurrentAddress()} writes only while the account still has the address the
 * caller loaded.
 *
 * The identity response reports `email_verified: true` while `email_verified_at` is set, and
 * omits the claim otherwise.
 */
final class EmailProof
{
    /**
     * A secret mailed to `$user->email` was presented. Mark that address proven, unless the
     * account's address has changed since `$user` was loaded or it is already proven.
     */
    public function proveCurrentAddress(User $user): void
    {
        $email = (string) $user->email;
        if ($email === '') {
            return;
        }

        User::query()
            ->whereKey($user->getKey())
            ->where('email', $email)
            ->whereNull('email_verified_at')
            ->update(['email_verified_at' => now()]);
    }

    /**
     * The account is leaving `$formerEmail`. Withdraw every outstanding code and reset link
     * mailed there. Call inside the transaction that changes the address.
     */
    public function forgetAddress(User $user, string $formerEmail): void
    {
        DB::table(config('bherila-auth.two_factor.table', 'auth_two_factor_attempts'))->where('user_id', $user->getKey())->delete();
        DB::table('password_reset_tokens')->where('email', $formerEmail)->delete();
    }
}
