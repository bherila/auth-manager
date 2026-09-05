<?php

use App\Support\AuthManagerProfile;

$profile = AuthManagerProfile::fromEnvironment();
$issuer = AuthManagerProfile::validatedIssuerUrl(
    env('AUTH_MANAGER_OAUTH_ISSUER', $profile->defaultIssuer()),
    'AUTH_MANAGER_OAUTH_ISSUER',
);
$resource = AuthManagerProfile::validatedAbsoluteUrl(
    env('AUTH_MANAGER_OAUTH_RESOURCE', $profile->defaultResource()),
    'AUTH_MANAGER_OAUTH_RESOURCE',
);
$themeCookieDomain = AuthManagerProfile::validatedThemeCookieDomain(
    env('AUTH_MANAGER_THEME_COOKIE_DOMAIN', $profile->defaultThemeCookieDomain()),
);
$themeHosts = AuthManagerProfile::validatedThemeAllowedHosts(array_values(array_filter(array_map(
    'trim',
    explode(',', (string) env('AUTH_MANAGER_THEME_ALLOWED_HOSTS', implode(',', $profile->defaultThemeAllowedHosts()))),
), static fn (string $host): bool => $host !== '')), $themeCookieDomain);

return [
    'profile' => $profile->value,
    'issuer' => $issuer,
    'resource' => $resource,
    'scopes' => $profile->scopes(),
    'resource_required_scopes' => $profile->resourceRequiredScopes(),
    'oauth_server' => $profile === AuthManagerProfile::ResourceServer,
    'dynamic_client_registration' => $profile === AuthManagerProfile::ResourceServer,
    'introspection' => $profile === AuthManagerProfile::ResourceServer,
    'theme' => [
        'cookie_domain' => $themeCookieDomain,
        'allowed_hosts' => $themeHosts,
    ],
];
