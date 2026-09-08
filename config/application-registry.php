<?php

return [
    // Populate and verify the registry before replacing legacy static-client launch links.
    'launch_enabled' => (bool) env('AUTH_MANAGER_APP_REGISTRY_LAUNCH_ENABLED', false),
];
