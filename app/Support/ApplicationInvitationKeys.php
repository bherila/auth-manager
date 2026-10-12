<?php

namespace App\Support;

use App\Models\RegisteredApplication;
use InvalidArgumentException;

/**
 * The public keys an application's actor assertions are verified with, for admission invitations
 * it requests ({@see ApplicationInvitations}).
 *
 * The application holds the private half; this provider only ever reads public keys. Each key is
 * pinned to one application, so a key can never speak for another, and an application may list
 * several key ids while it rotates.
 *
 * Validated at use time, like the delegated access maps: a malformed value refuses every request
 * with `invalid_configuration` and reports the entry position and rule once, never the value.
 */
final class ApplicationInvitationKeys
{
    public const ENVIRONMENT = 'AUTH_MANAGER_APPLICATION_INVITATION_KEYS';

    private mixed $source = null;

    private bool $resolvedOnce = false;

    /** @var array<string, array<string, string>>|InvalidArgumentException */
    private array|InvalidArgumentException $resolved = [];

    /**
     * Public key paths by key id for this application; empty when it has none.
     *
     * @return array<string, string>
     *
     * @throws InvalidArgumentException when the configured value is malformed
     */
    public function for(string $application): array
    {
        $source = config('application-invitations.keys_environment');
        if (! $this->resolvedOnce || $source !== $this->source) {
            // Resolved, and a problem reported, once per request (the service is scoped), unless
            // the configuration itself changes.
            $this->resolvedOnce = true;
            $this->source = $source;
            try {
                $this->resolved = self::parse($source);
            } catch (InvalidArgumentException $failure) {
                $this->resolved = $failure;
                report($failure);
            }
        }
        if ($this->resolved instanceof InvalidArgumentException) {
            throw $this->resolved;
        }

        return $this->resolved[$application] ?? [];
    }

    /**
     * @return array<string, array<string, string>> application => key id => absolute public key path
     *
     * @throws InvalidArgumentException
     */
    public static function parse(mixed $value): array
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return [];
        }
        if (! is_string($value)) {
            throw self::invalid('must be a comma-separated list of application|key-id|/absolute/public/key/path entries');
        }

        $keys = [];
        $keyIds = [];
        $paths = [];
        foreach (explode(',', $value) as $index => $entry) {
            $label = 'entry '.($index + 1);
            $fields = array_map('trim', explode('|', trim($entry)));
            if (count($fields) !== 3) {
                throw self::invalid("{$label} must have the form application|key-id|/absolute/public/key/path");
            }
            [$application, $keyId, $path] = $fields;
            if (strlen($application) > RegisteredApplication::KEY_MAX_LENGTH || preg_match(RegisteredApplication::KEY_PATTERN, $application) !== 1) {
                throw self::invalid("{$label} has an invalid application key");
            }
            if (preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $keyId) !== 1) {
                throw self::invalid("{$label} key id must be 1 to 128 letters, digits, dots, dashes or underscores");
            }
            if (! str_starts_with($path, '/')) {
                throw self::invalid("{$label} public key path must be absolute");
            }
            // A key id or key file shared between applications would let one speak for the other.
            if (isset($keyIds[$keyId]) || isset($paths[$path])) {
                throw self::invalid("{$label} reuses a key id or key file already listed");
            }
            $keyIds[$keyId] = true;
            $paths[$path] = true;
            $keys[$application][$keyId] = $path;
        }

        return $keys;
    }

    private static function invalid(string $rule): InvalidArgumentException
    {
        return new InvalidArgumentException(self::ENVIRONMENT.' '.$rule.'.');
    }
}
