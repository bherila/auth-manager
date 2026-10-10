<?php

namespace App\Support;

use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Carbon\CarbonImmutable;
use Throwable;

/**
 * The read-only observations a contract version 3 application may report about an account, and
 * how the access page shows them.
 *
 * They are what the application says it saw: never authorization, never part of a revision. A
 * field the application does not report is not shown at all; one it reports as null is shown as
 * not recorded. The contract has already checked each value is an ISO-8601 timestamp.
 */
final class DelegatedMetadata
{
    /** Each field the contract allows ({@see DelegatedContract::STATE_METADATA}) and its label, in display order. */
    public const LABELS = [
        'provisioned_at' => 'Added',
        'first_sign_in_at' => 'First sign-in',
        'last_seen_at' => 'Last seen',
    ];

    /**
     * The fields any of these entries reports, in display order, so a list shows a column only for
     * what the application actually sends.
     *
     * @param  iterable<array<string, mixed>>  $entries
     * @return array<string, string> field => label
     */
    public static function reported(iterable $entries): array
    {
        $present = [];
        foreach ($entries as $entry) {
            foreach (array_keys(self::LABELS) as $field) {
                if (array_key_exists($field, $entry)) {
                    $present[$field] = true;
                }
            }
        }

        return array_intersect_key(self::LABELS, $present);
    }

    /** A reported timestamp in the instance's time zone, or "Not recorded" for null. */
    public static function display(mixed $value): string
    {
        if (! is_string($value)) {
            return 'Not recorded';
        }
        try {
            return CarbonImmutable::parse($value)->setTimezone((string) config('app.timezone', 'UTC'))->format('Y-m-d H:i T');
        } catch (Throwable) {
            return 'Not recorded';
        }
    }
}
