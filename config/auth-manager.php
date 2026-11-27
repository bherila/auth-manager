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

// Raised by the operator after restoring the database from a backup (docs/recovery.md). Sent to
// relying applications with every identity, so a consumer can tell that the provider's state was
// rolled back and stop trusting sessions it established before.
$recoveryEpoch = filter_var(env('AUTH_MANAGER_RECOVERY_EPOCH', 1), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1],
]);
if ($recoveryEpoch === false) {
    throw new InvalidArgumentException('AUTH_MANAGER_RECOVERY_EPOCH must be a positive integer.');
}
$highWaterPath = env('AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH', storage_path('app/private/auth-manager/recovery-high-water.json'));
if (! is_string($highWaterPath) || $highWaterPath === '' || preg_match('#^(/|[A-Za-z]:[\\\\/])#', $highWaterPath) !== 1) {
    throw new InvalidArgumentException('AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH must be an absolute file path.');
}
$auditExportDisk = env('AUTH_MANAGER_AUDIT_EXPORT_DISK');
if ($auditExportDisk !== null && $auditExportDisk !== '' && (! is_string($auditExportDisk) || preg_match('/^[A-Za-z0-9._-]+$/', $auditExportDisk) !== 1)) {
    throw new InvalidArgumentException('AUTH_MANAGER_AUDIT_EXPORT_DISK must be the name of a filesystem disk.');
}
$auditExportPrefix = env('AUTH_MANAGER_AUDIT_EXPORT_PREFIX', 'audit');
if (! is_string($auditExportPrefix) || preg_match('#^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$#', $auditExportPrefix) !== 1) {
    throw new InvalidArgumentException('AUTH_MANAGER_AUDIT_EXPORT_PREFIX must be a relative path of letters, digits, dots, dashes and underscores.');
}
$auditExportBatch = filter_var(env('AUTH_MANAGER_AUDIT_EXPORT_BATCH_SIZE', 5000), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 50000],
]);
if ($auditExportBatch === false) {
    throw new InvalidArgumentException('AUTH_MANAGER_AUDIT_EXPORT_BATCH_SIZE must be an integer from 1 to 50000.');
}
$auditExportState = env('AUTH_MANAGER_AUDIT_EXPORT_STATE_PATH', storage_path('app/private/auth-manager/audit-export-state.json'));
if (! is_string($auditExportState) || $auditExportState === '' || preg_match('#^(/|[A-Za-z]:[\\\\/])#', $auditExportState) !== 1) {
    throw new InvalidArgumentException('AUTH_MANAGER_AUDIT_EXPORT_STATE_PATH must be an absolute file path.');
}

return [
    'password_min_length' => $passwordMinLength,
    // New accounts get a random ULID as their subject instead of their id (docs/identity-subjects.md).
    // Turn on only once every application signing in through this instance accepts non-numeric
    // subjects. Existing accounts keep theirs either way.
    'subjects' => [
        'opaque' => $signInSetting('AUTH_MANAGER_OPAQUE_SUBJECTS', false),
    ],
    'recovery' => [
        'epoch' => $recoveryEpoch,
        // Answer identity status with a retryable 503 while the database is behind the highest
        // audit record this instance has seen, until the operator raises the epoch.
        'high_water_guard' => $signInSetting('AUTH_MANAGER_RECOVERY_HIGH_WATER_GUARD', true),
        // Must survive a database restore: never inside the database or anything restored with it.
        'high_water_path' => $highWaterPath,
        // The hourly off-box copy of the audit log that step 4 of a restore reads (docs/recovery.md):
        // append-only objects on this filesystem disk, ideally an S3 bucket with Object Lock in
        // another account. Unset, the export refuses and is not scheduled.
        'audit_export' => [
            'disk' => $auditExportDisk === '' ? null : $auditExportDisk,
            'prefix' => $auditExportPrefix,
            'batch_size' => $auditExportBatch,
            // Where to resume when the destination lists nothing; the destination itself decides otherwise.
            'state_path' => $auditExportState,
        ],
    ],
    'test_logins' => [
        'ticket_clients' => array_values(array_filter(array_map('trim', explode(',', (string) env('AUTH_MANAGER_TEST_LOGIN_TICKET_CLIENTS', ''))))),
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
    // Identity-status and tombstone reads by relying applications. Every consumer behind one
    // egress IP shares the per-IP budget, so it only bounds unauthenticated traffic; each
    // authenticated client then has its own budget per operation, so one busy or broken
    // consumer cannot starve another's status checks.
    'reconciliation' => [
        'per_ip_per_minute' => max(1, (int) env('AUTH_MANAGER_RECONCILIATION_PER_IP_PER_MINUTE', 600)),
        'status_per_client_per_minute' => max(1, (int) env('AUTH_MANAGER_RECONCILIATION_STATUS_PER_CLIENT_PER_MINUTE', 300)),
        'tombstones_per_client_per_minute' => max(1, (int) env('AUTH_MANAGER_RECONCILIATION_TOMBSTONES_PER_CLIENT_PER_MINUTE', 120)),
    ],
    'profile' => $profile->value,
    'application_registration' => [
        // Creating identities is a separate, operator-approved authority; off by default.
        'applications' => array_values(array_filter(array_map('trim', explode(',', (string) env('AUTH_MANAGER_APPLICATION_REGISTRATION', ''))))),
        'additional_client_grants' => json_decode((string) env('AUTH_MANAGER_APPLICATION_REGISTRATION_CLIENT_GRANTS', '{}'), true),
    ],
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
