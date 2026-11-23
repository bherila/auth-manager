<?php

namespace BWH\AuthManager\Support;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;

/**
 * The subject this provider sends to relying applications: `users.subject`, never the row id.
 *
 * Applications bind their accounts to (provider, subject), so a subject must never be issued to
 * a second person. One is 1 to 64 ASCII letters and digits, compared case-sensitively. An
 * all-digit subject is always the decimal id of the account that holds it: that is how every
 * account created before subjects had a column of their own was identified, and keeping the rule
 * means an id this directory allocates later can never collide with one.
 */
final class ProviderSubjects
{
    public const PATTERN = '/^[0-9A-Za-z]{1,64}$/D';

    /**
     * A subject this provider could have issued. An all-digit one is a canonical positive id.
     *
     * @phpstan-assert-if-true string $subject
     */
    public static function valid(mixed $subject): bool
    {
        return is_string($subject) && preg_match(self::PATTERN, $subject) === 1
            && (! self::numeric($subject) || self::canonicalId($subject));
    }

    /** The canonical decimal form of a positive signed 64-bit id: no sign, no leading zero. */
    public static function canonicalId(mixed $subject): bool
    {
        return is_string($subject) && preg_match('/^[1-9][0-9]{0,18}$/D', $subject) === 1
            && (strlen($subject) < 19 || strcmp($subject, (string) PHP_INT_MAX) <= 0);
    }

    /** Whether a subject is all digits, and so may only ever be the holder's own id. */
    public static function numeric(string $subject): bool
    {
        return $subject !== '' && ctype_digit($subject);
    }

    /**
     * The subject a new account receives before it is inserted, or null when it takes its own id
     * once the row exists.
     */
    public function forNewAccount(): ?string
    {
        return null;
    }

    /**
     * Whether a deleted identity was known by this subject. Tombstones written before the text
     * column existed, or by the previous release while it was being added, carry only the id.
     */
    public function retired(string $subject, ?ConnectionInterface $connection = null): bool
    {
        $tombstones = ($connection ?? DB::connection())->table('identity_tombstones');

        return $tombstones->where('provider_subject', $subject)
            ->when(self::canonicalId($subject), fn ($query) => $query
                ->orWhere(fn ($legacy) => $legacy->whereNull('provider_subject')->where('subject', $subject)))
            ->exists();
    }
}
