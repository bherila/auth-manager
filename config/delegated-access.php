<?php

return [
    'enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_ENABLED', false),
    // Remains off until a trusted recent-credential-confirmation route is available.
    'writes_enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED', false),
    // Writes also need the application listed here (comma-separated keys), so
    // switching writes on for one application changes no other.
    'writes_applications' => array_values(array_filter(array_map('trim', explode(',', (string) env('AUTH_MANAGER_DELEGATED_ACCESS_WRITES_APPLICATIONS', ''))))),
    // Invitations by email from the application-access page. Also needs writes for the
    // application, contract version 2, and `access-invite:<application>` for the inviter.
    'invitations' => [
        'enabled' => (bool) env('AUTH_MANAGER_INVITATIONS_ENABLED', false),
        'expires_after_days' => 7,
        // Invitations created or resent per inviter per hour, and per recipient address per day.
        'per_inviter_per_hour' => 20,
        'per_recipient_per_day' => 5,
    ],
    'issuer' => env('AUTH_MANAGER_DELEGATED_ACCESS_ISSUER'),
    'key_id' => env('AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID'),
    'private_key_path' => env('AUTH_MANAGER_DELEGATED_ACCESS_PRIVATE_KEY_PATH'),
    // Per-application signing keys, comma-separated application|key-id|/absolute/private/key/path.
    // A listed application is signed with its own key; the key_id/private_key_path pair above is a
    // fallback for reads only, and writes need the application's own key. Validated at use time by
    // App\Support\DelegatedAccessKeys.
    'keys_environment' => env('AUTH_MANAGER_DELEGATED_ACCESS_KEYS'),
    // Deployment-owned map: application key => ['endpoint' => absolute HTTPS URL,
    // 'contract_version' => 1|2 (default 1)]. The version is agreed with the application and
    // never negotiated at runtime; see bherila/auth-laravel's delegated access contract.
    // Never derive entries from launch URLs, OAuth redirects, or browser input.
    // Normally empty: the map comes from applications_environment below. A literal map here
    // takes precedence over it. Both are validated at use time by
    // App\Support\DelegatedAccessApplications, never while configuration loads.
    'applications' => [],
    // Raw comma-separated key|https://endpoint|contract_version entries; empty or unset means
    // none. A malformed value disables delegated access only: every delegated call is refused
    // with invalid_configuration. Check it with `php artisan auth-manager:delegated-access:check`.
    'applications_environment' => env('AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS'),
];
