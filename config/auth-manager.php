<?php

use BWH\AuthManager\Support\AuthManagerProfile;
use BWH\AuthManager\Support\Mount;
use BWH\AuthManager\Support\TestLoginAddresses;

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

$passwordMinLength = filter_var(env('AUTH_MANAGER_PASSWORD_MIN_LENGTH', 12), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 8, 'max_range' => 72],
]);
if ($passwordMinLength === false) {
    throw new InvalidArgumentException('AUTH_MANAGER_PASSWORD_MIN_LENGTH must be an integer from 8 to 72.');
}

// Refused rather than read as false: a mistyped value must not quietly turn a sign-in control off.
$signInSetting = static function (string $name, bool $default): bool {
    $value = filter_var(env($name, $default), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($value === null) {
        throw new InvalidArgumentException("{$name} must be true or false.");
    }

    return $value;
};

$trustedDeviceDays = filter_var(env('AUTH_MANAGER_TRUSTED_DEVICE_DAYS', 30), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 365],
]);
if ($trustedDeviceDays === false) {
    throw new InvalidArgumentException('AUTH_MANAGER_TRUSTED_DEVICE_DAYS must be an integer from 1 to 365.');
}

$testLoginHours = filter_var(env('AUTH_MANAGER_TEST_LOGIN_MAX_HOURS', 24), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 168],
]);
if ($testLoginHours === false) {
    throw new InvalidArgumentException('AUTH_MANAGER_TEST_LOGIN_MAX_HOURS must be an integer from 1 to 168.');
}

return [
    'password_min_length' => $passwordMinLength,
    'test_logins' => [
        'allowed_domains' => TestLoginAddresses::configuredDomains((string) env('AUTH_MANAGER_TEST_LOGIN_DOMAINS', '')),
        'max_lifetime_hours' => $testLoginHours,
    ],
    'sign_in' => [
        'code_after_password' => $signInSetting('AUTH_MANAGER_REQUIRE_CODE_AFTER_PASSWORD', false),
        'code_only' => $signInSetting('AUTH_MANAGER_ALLOW_CODE_ONLY_SIGN_IN', true),
        'password_reset' => $signInSetting('AUTH_MANAGER_ALLOW_PASSWORD_RESET', false),
        'trusted_devices' => $signInSetting('AUTH_MANAGER_ALLOW_TRUSTED_DEVICES', false),
        'trusted_device_days' => $trustedDeviceDays,
    ],
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
