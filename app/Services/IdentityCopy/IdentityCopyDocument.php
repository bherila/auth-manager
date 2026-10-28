<?php

namespace App\Services\IdentityCopy;

use Carbon\CarbonImmutable;
use InvalidArgumentException;

/**
 * The wire format that carries selected identities from one instance to another.
 *
 * It holds exactly what a person needs to sign in on the receiving instance with their existing
 * subject and password, and nothing bound to the sending instance: no sessions, remember tokens,
 * OAuth codes or tokens, passkeys (bound to the sending RP ID), client grants (bound to the
 * sending instance's clients), audit history, tombstones or invitations.
 */
final class IdentityCopyDocument
{
    public const FORMAT = 'auth-manager.identity-copy';

    public const VERSION = 1;

    /** Columns carried for each person. */
    public const COLUMNS = [
        'id',
        'name',
        'email',
        'email_verified_at',
        'password',
        'user_role',
        'disabled_at',
        'last_login_date',
        'created_at',
        'updated_at',
    ];

    /**
     * Columns that must agree for an existing row to count as the same copy.
     *
     * `last_login_date` and `updated_at` move on their own once a person uses the receiving
     * instance, so they are copied on creation but never compared.
     */
    public const COMPARED = [
        'name',
        'email',
        'email_verified_at',
        'password',
        'user_role',
        'disabled_at',
    ];

    private const TIMESTAMPS = ['email_verified_at', 'disabled_at', 'last_login_date', 'created_at', 'updated_at'];

    /**
     * @param  list<array<string, mixed>>  $users
     */
    private function __construct(
        public readonly int $nextIdFloor,
        public readonly array $users,
    ) {}

    /**
     * @param  list<array<string, mixed>>  $users
     */
    public static function make(int $nextIdFloor, array $users): self
    {
        return self::validated(['format' => self::FORMAT, 'version' => self::VERSION, 'next_id_floor' => $nextIdFloor, 'users' => $users]);
    }

    public static function decode(string $json): self
    {
        try {
            $decoded = json_decode($json, true, 16, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            throw new InvalidArgumentException('The input is not valid JSON.');
        }

        if (! is_array($decoded)) {
            throw new InvalidArgumentException('The input is not an identity copy document.');
        }

        return self::validated($decoded);
    }

    public function encode(): string
    {
        return json_encode([
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'next_id_floor' => $this->nextIdFloor,
            'users' => $this->users,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Normalize a stored timestamp so two engines' spellings of one instant compare equal.
     */
    public static function timestamp(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (! is_string($value) && ! $value instanceof \DateTimeInterface) {
            throw new InvalidArgumentException('A timestamp is not a date string.');
        }

        // MySQL's zero date is not an instant; parsing it would invent year -1.
        if (is_string($value) && str_starts_with($value, '0000-00-00')) {
            throw new InvalidArgumentException('A timestamp is a zero date.');
        }

        try {
            return CarbonImmutable::parse($value)->format('Y-m-d H:i:s');
        } catch (\Throwable) {
            throw new InvalidArgumentException('A timestamp could not be parsed.');
        }
    }

    /**
     * @param  array<mixed>  $document
     */
    private static function validated(array $document): self
    {
        if (array_keys($document) !== ['format', 'version', 'next_id_floor', 'users']) {
            throw new InvalidArgumentException('The document has missing or unexpected top-level fields.');
        }

        if ($document['format'] !== self::FORMAT || $document['version'] !== self::VERSION) {
            throw new InvalidArgumentException('The document is not a supported identity copy format.');
        }

        $floor = $document['next_id_floor'];
        if (! is_int($floor) || $floor < 1) {
            throw new InvalidArgumentException('next_id_floor must be a positive integer.');
        }

        if (! is_array($document['users']) || ! array_is_list($document['users']) || $document['users'] === []) {
            throw new InvalidArgumentException('The document must list at least one person.');
        }

        $users = [];
        $ids = [];
        $emails = [];

        foreach ($document['users'] as $position => $user) {
            if (! is_array($user) || array_keys($user) !== self::COLUMNS) {
                throw new InvalidArgumentException("Entry {$position} does not have exactly the expected fields.");
            }

            $id = $user['id'];
            if (! is_int($id) || $id < 1) {
                throw new InvalidArgumentException("Entry {$position} has an invalid id.");
            }

            if ($id >= $floor) {
                throw new InvalidArgumentException("Entry {$position} has an id at or above next_id_floor.");
            }

            foreach (['name', 'email', 'password', 'user_role'] as $column) {
                if (! is_string($user[$column]) || trim($user[$column]) === '') {
                    throw new InvalidArgumentException("Subject {$id} has an empty {$column}.");
                }
            }

            // A copied credential must be a password hash. Anything else would either never verify
            // or, worse, be hashed again by a later write and silently lock the person out.
            if ((password_get_info($user['password'])['algoName'] ?? 'unknown') === 'unknown') {
                throw new InvalidArgumentException("Subject {$id} does not carry a recognized password hash.");
            }

            foreach (self::TIMESTAMPS as $column) {
                $user[$column] = self::timestamp($user[$column]);
            }

            $email = strtolower(trim($user['email']));
            if (isset($ids[$id]) || isset($emails[$email])) {
                throw new InvalidArgumentException("Subject {$id} is listed twice, or shares an email address with another entry.");
            }

            $ids[$id] = true;
            $emails[$email] = true;
            $users[] = $user;
        }

        return new self($floor, $users);
    }
}
