<?php

return [
    'enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_ENABLED', false),
    // Remains off until a trusted recent-credential-confirmation route is available.
    'writes_enabled' => (bool) env('AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED', false),
    'issuer' => env('AUTH_MANAGER_DELEGATED_ACCESS_ISSUER'),
    'key_id' => env('AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID'),
    'private_key_path' => env('AUTH_MANAGER_DELEGATED_ACCESS_PRIVATE_KEY_PATH'),
    // Deployment-owned map: application key => ['endpoint' => absolute HTTPS URL].
    // Never derive entries from launch URLs, OAuth redirects, or browser input.
    'applications' => [],
];
