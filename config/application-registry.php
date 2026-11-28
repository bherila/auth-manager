<?php

return [
    // Populate and verify the registry before replacing legacy static-client launch links.
    'launch_enabled' => (bool) env('AUTH_MANAGER_APP_REGISTRY_LAUNCH_ENABLED', false),
    // Optional registry key for non-administrators visiting the provider home.
    'default_application' => env('AUTH_MANAGER_DEFAULT_APPLICATION'),
];
