<?php

namespace App\Support;

use App\Models\RegisteredApplication;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use InvalidArgumentException;

/**
 * Per-application signing keys for delegated access assertions.
 *
 * With one key for every application, whoever holds it can mint an assertion any
 * connected application accepts, and rotating it touches all of them. Each
 * application listed here is signed with its own key and trusts only that key's
 * public half, so a key reaches one application.
 *
 * The instance-wide key remains a fallback for reads while applications move over.
 * Writes need the application's own key: {@see DelegatedAccessPermissions::writesEnabled()}.
 *
 * Validated at use time, like the application map: a malformed value refuses every
 * delegated call with `invalid_configuration` and reports the entry position and rule,
 * never the value.
 */
final class DelegatedAccessKeys
{
    public const ENVIRONMENT = 'AUTH_MANAGER_DELEGATED_ACCESS_KEYS';

    /**
     * The key this application is signed with: its own, or the instance-wide fallback.
     *
     * @return array{key_id: mixed, private_key_path: mixed, own: bool}
     *
     * @throws DelegatedAccessException when the value is malformed
     */
    public function for(string $application): array
    {
        $own = $this->own($application);

        return $own === null
            ? ['key_id' => config('delegated-access.key_id'), 'private_key_path' => config('delegated-access.private_key_path'), 'own' => false]
            : [...$own, 'own' => true];
    }

    /**
     * @return array{key_id: string, private_key_path: string}|null
     *
     * @throws DelegatedAccessException when the value is malformed
     */
    public function own(string $application): ?array
    {
        try {
            return self::parse(config('delegated-access.keys_environment'))[$application] ?? null;
        } catch (InvalidArgumentException $failure) {
            report($failure);

            throw new DelegatedAccessException('invalid_configuration');
        }
    }

    /**
     * @return array<string, array{key_id: string, private_key_path: string}>
     *
     * @throws InvalidArgumentException
     */
    public static function parse(mixed $value): array
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return [];
        }
        if (! is_string($value)) {
            throw self::invalid('must be a comma-separated list of application|key-id|/absolute/private/key/path entries');
        }

        $keys = [];
        foreach (explode(',', $value) as $index => $entry) {
            $label = 'entry '.($index + 1);
            $fields = array_map('trim', explode('|', trim($entry)));
            if (count($fields) !== 3) {
                throw self::invalid("{$label} must have the form application|key-id|/absolute/private/key/path");
            }
            [$application, $keyId, $path] = $fields;
            if (strlen($application) > RegisteredApplication::KEY_MAX_LENGTH || preg_match(RegisteredApplication::KEY_PATTERN, $application) !== 1) {
                throw self::invalid("{$label} has an invalid application key");
            }
            if (array_key_exists($application, $keys)) {
                throw self::invalid("{$label} repeats an application key");
            }
            if (preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $keyId) !== 1) {
                throw self::invalid("{$label} key id must be 1 to 128 letters, digits, dots, dashes or underscores");
            }
            if (! str_starts_with($path, '/')) {
                throw self::invalid("{$label} private key path must be absolute");
            }

            $keys[$application] = ['key_id' => $keyId, 'private_key_path' => $path];
        }

        return $keys;
    }

    private static function invalid(string $rule): InvalidArgumentException
    {
        return new InvalidArgumentException(self::ENVIRONMENT.' '.$rule.'.');
    }
}
