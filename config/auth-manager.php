<?php

use BWH\AuthManager\Support\AuthManagerProfile;
use BWH\AuthManager\Support\Mount;

$profile = AuthManagerProfile::fromEnvironment();
// Embedded in a host application (docs/embedded-mode.md), nothing defaults to a deployment
// of this repository: the issuer is the mount URL, and there is no shared theme cookie.
$embedded = Mount::embedded();
$issuer = AuthManagerProfile::validatedIssuerUrl(
    env('AUTH_MANAGER_OAUTH_ISSUER', $embedded
        ? rtrim((string) config('app.url'), '/').Mount::path('/')
        : $profile->defaultIssuer()),
    'AUTH_MANAGER_OAUTH_ISSUER',
    $embedded ? Mount::path('/') : null,
);
$resource = AuthManagerProfile::validatedAbsoluteUrl(
    env('AUTH_MANAGER_OAUTH_RESOURCE', $embedded && $profile->defaultResource() !== null
        ? $issuer.'/api/v1'
        : $profile->defaultResource()),
    'AUTH_MANAGER_OAUTH_RESOURCE',
);
$themeCookieDomain = AuthManagerProfile::validatedThemeCookieDomain(
    env('AUTH_MANAGER_THEME_COOKIE_DOMAIN', $embedded ? null : $profile->defaultThemeCookieDomain()),
);
$themeHosts = AuthManagerProfile::validatedThemeAllowedHosts(array_values(array_filter(array_map(
    'trim',
    explode(',', (string) env('AUTH_MANAGER_THEME_ALLOWED_HOSTS', $embedded ? '' : implode(',', $profile->defaultThemeAllowedHosts()))),
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
