<?php

return [
    'enabled' => (bool) env('AUTH_BRANDING_ENABLED', false),
    'logo_light' => env('AUTH_BRANDING_LOGO_LIGHT'),
    'logo_dark' => env('AUTH_BRANDING_LOGO_DARK'),
    'favicon' => env('AUTH_BRANDING_FAVICON'),
    'stylesheet' => env('AUTH_BRANDING_STYLESHEET'),
    // The logo artwork already spells out the application name (a wordmark), so the name is
    // carried as the logo's alt text instead of being printed again beside it.
    'logo_includes_name' => (bool) env('AUTH_BRANDING_LOGO_INCLUDES_NAME', false),
];
