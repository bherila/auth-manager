<?php

namespace BWH\AuthManager\Listeners;

use Illuminate\Foundation\Events\DiagnosingHealth;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResourceServer;
use RuntimeException;
use Throwable;

/**
 * Fails /up when Passport cannot load the OAuth signing keys.
 *
 * Checked whatever the agent OAuth server flag says: Passport signs this identity
 * provider's own tokens either way.
 *
 * Passport reads its keys on the first token request and refuses a key file other
 * users can read. Without this, unusable keys leave /up, the OAuth metadata and an
 * unauthenticated MCP probe all healthy while every token request fails. The
 * message is fixed and non-empty: Laravel's health route answers
 * 500 only for a non-empty message, and the cause, which can name a host path,
 * is reported rather than shown.
 */
final class EnsureOAuthSigningKeysLoad
{
    public function handle(DiagnosingHealth $event): void
    {
        try {
            app(AuthorizationServer::class);
            app(ResourceServer::class);
        } catch (Throwable $exception) {
            throw new RuntimeException('OAuth signing keys cannot be loaded.', previous: $exception);
        }
    }
}
