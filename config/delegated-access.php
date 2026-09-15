<?php

return [
    'enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_ENABLED', false),
    // Remains off until a trusted recent-credential-confirmation route is available.
    'writes_enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED', false),
    'issuer' => env('AUTH_MANAGER_DELEGATED_ACCESS_ISSUER'),
    'key_id' => env('AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID'),
    'private_key_path' => env('AUTH_MANAGER_DELEGATED_ACCESS_PRIVATE_KEY_PATH'),
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
