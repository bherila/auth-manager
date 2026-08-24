<?php

use App\Http\Middleware\ThrottleTwoFactorVerify;
use App\Models\User;

return [
    'routes' => [
        'enabled' => true,
        'prefix' => 'api',
        'middleware' => ['web', ThrottleTwoFactorVerify::class],
        'passkeys' => true,
        'password_resets' => false,
        'change_password' => false,
        'two_factor' => true,
    ],

    'migrations' => [
        'drop_tables_on_rollback' => false,
    ],

    'audit' => [
        'driver' => env('BHERILA_AUTH_AUDIT_DRIVER', 'database'),
        'table' => 'auth_audit_log',
        'routes_enabled' => env('BHERILA_AUTH_AUDIT_ROUTES', false),
        'retention_days' => env('BHERILA_AUTH_AUDIT_RETENTION_DAYS'),
        'admin_ability' => env('BHERILA_AUTH_AUDIT_ADMIN_ABILITY'),
    ],

    'throttle' => [
        // Brute-force lockout backed by auth_audit_log rows. On by default; override per-env.
        'enabled' => env('BHERILA_AUTH_THROTTLE_ENABLED', true),
        'max_attempts' => env('BHERILA_AUTH_THROTTLE_MAX_ATTEMPTS', 5),
        'decay_minutes' => env('BHERILA_AUTH_THROTTLE_DECAY_MINUTES', 15),
        // email, ip, or email_ip. Invalid values fall back to email_ip.
        'key' => env('BHERILA_AUTH_THROTTLE_KEY', 'email_ip'),
        'record_blocked' => env('BHERILA_AUTH_THROTTLE_RECORD_BLOCKED', true),
    ],

    'password_resets' => [
        'reset_url' => env('BHERILA_AUTH_PASSWORD_RESET_URL', env('APP_URL', '').'/reset-password/{token}?email={email}'),
        'request_url' => env('BHERILA_AUTH_PASSWORD_REQUEST_URL', '/forgot-password'),
        'redirect_after_reset' => env('BHERILA_AUTH_PASSWORD_RESET_REDIRECT', '/'),
        'mail_subject' => env('BHERILA_AUTH_PASSWORD_RESET_MAIL_SUBJECT', 'Reset your :app password'),
        'notice_subject' => env('BHERILA_AUTH_PASSWORD_NOTICE_MAIL_SUBJECT', 'Your :app password was changed'),
        'verify_email_on_reset' => false,
    ],

    'two_factor' => [
        'table' => 'auth_two_factor_attempts',
        'expires_minutes' => 15,
        'allow_test_code' => env('BHERILA_AUTH_ALLOW_TEST_2FA_CODE', env('APP_ENV') !== 'production'),
        'test_code' => '999999',
        'mail_subject' => env('BHERILA_AUTH_TWO_FACTOR_MAIL_SUBJECT', 'Verify your login - :app'),
        'login_url' => env('BHERILA_AUTH_LOGIN_URL', '/login'),
        'session_user_key' => 'bherila_auth_2fa_user_id',
        'session_remember_key' => 'bherila_auth_2fa_remember',
    ],

    'passkeys' => [
        'table' => 'webauthn_credentials',
        'rp_name' => env('WEBAUTHN_RP_NAME', env('APP_NAME', 'App')),
        // Must be declared here, not only in the package default: mergeConfigFrom is a
        // shallow merge, so this file's `passkeys` array replaces the package's entirely.
        // A key present only upstream silently resolves to null.
        'rp_id' => env('WEBAUTHN_RP_ID'),
        'allowed_origins' => array_filter(array_map('trim', explode(',', env('WEBAUTHN_ALLOWED_ORIGINS', '')))),
        'timeout' => 60000,
        'resident_key' => env('WEBAUTHN_RESIDENT_KEY', 'preferred'),
        'user_verification' => env('WEBAUTHN_USER_VERIFICATION', 'preferred'),
    ],

    'users' => [
        'model' => config('auth.providers.users.model', User::class),
        'name_attribute' => 'name',
        'email_attribute' => 'email',
        'force_change_password_attribute' => null,
    ],
];
