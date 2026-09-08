<?php

return [
    'enabled' => (bool) env('AUTH_BRANDING_ENABLED', false),
    'logo_light' => env('AUTH_BRANDING_LOGO_LIGHT'),
    'logo_dark' => env('AUTH_BRANDING_LOGO_DARK'),
    'favicon' => env('AUTH_BRANDING_FAVICON'),
    'stylesheet' => env('AUTH_BRANDING_STYLESHEET'),
];
