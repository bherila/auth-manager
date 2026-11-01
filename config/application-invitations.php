<?php

/*
 * Admission invitations an application requests for itself: see docs/application-invitations.md.
 *
 * Off for every application unless its registry key is listed in `applications` and it has a
 * public key in `keys_environment`. Neither has a default.
 */
return [
    // Comma-separated registry keys of the applications that may request admission invitations.
    // Empty or unset: none may. Listing one changes no other.
    'applications' => array_values(array_filter(array_map('trim', explode(',', (string) env('AUTH_MANAGER_APPLICATION_INVITATIONS', ''))))),
    // Comma-separated application|key-id|/absolute/public/key/path entries: the RS256 public keys an
    // application's actor assertions are verified with. An application may list more than one key id
    // while it rotates. Validated at use time by BWH\AuthManager\Support\ApplicationInvitationKeys: a malformed
    // value refuses every request with invalid_configuration and reports the entry position and rule.
    'keys_environment' => env('AUTH_MANAGER_APPLICATION_INVITATION_KEYS'),
    // Connection for consumed assertion ids. Null is the default connection. It must be durable and
    // outside any business transaction (see BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore).
    'nonce_connection' => env('AUTH_MANAGER_APPLICATION_INVITATION_NONCE_CONNECTION'),
    // Invitations created or resent per application per hour and per actor per hour. The per
    // recipient address limit is shared with invitations sent from this provider's own pages
    // (delegated-access.invitations.per_recipient_per_day).
    'per_application_per_hour' => 100,
    'per_actor_per_hour' => 20,
    // Proof of the address before acceptance creates an account: the link always goes to the
    // application too, so the provider emails a one-time code to the invited address and creates the
    // account only once it is entered. A code expires, is spent by `max_attempts` wrong entries, and
    // at most `max_sends` are sent per link (a resend starts again); codes to one address are also
    // limited per hour across every invitation.
    'verification' => [
        'expires_minutes' => 15,
        'max_attempts' => 5,
        'max_sends' => 5,
        'per_address_per_hour' => 5,
    ],
];
