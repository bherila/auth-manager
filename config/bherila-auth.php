<?php

use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Http\Middleware\ThrottleTwoFactorVerify;
use App\Models\User;

$issuer = (string) config('auth-manager.issuer');
$resource = (string) config('auth-manager.resource');
$oauthServerEnabled = (bool) config('auth-manager.oauth_server');
$dcrEnabled = (bool) config('auth-manager.dynamic_client_registration');
$introspectionEnabled = (bool) config('auth-manager.introspection');
$introspectionClientId = env('AUTH_MANAGER_INTROSPECTION_CLIENT_ID');
$introspectionSecretHash = env('AUTH_MANAGER_INTROSPECTION_SECRET_HASH');
$passportPath = trim((string) config('passport.path', 'oauth'), '/');
$oauthEndpointBase = rtrim($issuer, '/').($passportPath === '' ? '' : '/'.$passportPath);

return [
    'routes' => [
        // These are the shared login, passkey, and account-protection routes;
        // they remain enabled for both deployments. OAuth issuance is gated
        // independently below.
        'enabled' => true,
        'prefix' => 'api',
        'middleware' => ['web', ThrottleTwoFactorVerify::class, RequireRecentPasskeyAuthentication::class],
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
        'allow_test_code' => env('BHERILA_AUTH_ALLOW_TEST_2FA_CODE', false),
        'test_code_environments' => ['local', 'testing'],
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

    // OAuth issuance is profile-aware. Legacy identity credentials remain
    // unbound; resource-profile credentials are pinned to its configured API.
    'oauth_server' => [
        'enabled' => $oauthServerEnabled,
        'issuer' => $issuer,
        'resource' => $resource,
        'authorization_endpoint' => $oauthEndpointBase.'/authorize',
        'token_endpoint' => $oauthEndpointBase.'/token',
        'registration_endpoint' => $dcrEnabled ? $oauthEndpointBase.'/register' : null,
        'scopes' => config('auth-manager.scopes'),
        'protected_resource_scopes' => config('auth-manager.resource_required_scopes'),
        // Passport accepts public requests and the confidential client-secret
        // methods below. DCR remains public-only because its controller
        // separately requires `none` before registering a client.
        'token_endpoint_auth_methods' => ['none', 'client_secret_basic', 'client_secret_post'],
        'protected_resource_metadata_url' => null,
        'auth_code_resource_column' => 'resource_uri',
        'resource_column' => 'resource_uri',
        'refresh_token_resource_column' => 'resource_uri',
        'authorization_response_issuer' => ['enabled' => false],
        'resource_required_scope' => null,
        'resource_required_scopes' => config('auth-manager.resource_required_scopes'),
        'dynamic_clients' => [
            'enabled' => $dcrEnabled,
            'required_columns' => ['dynamically_registered_at', 'scopes'],
            'registered_at_column' => 'dynamically_registered_at',
            'last_used_at_column' => 'last_used_at',
            'scopes_column' => 'scopes',
            'enforce_registered_scopes' => true,
        ],
        'authorization_state' => [
            'cache_prefix' => 'oauth-resource:',
            'ttl_seconds' => null,
        ],
        'consent' => [
            'app_name' => env('APP_NAME', 'Application'),
            'heading' => 'Connect :client to :app?',
            'intro' => 'This application is requesting access to your :app account.',
            'identity' => true,
            'trust_warning' => 'Only continue if you recognize and trust this application. You can disconnect it later.',
            'dynamic_client_warning' => 'This application registered automatically. After approval, your browser returns to:',
            'policy_notice' => 'Your current permissions still apply to every request.',
            'approve_label' => 'Authorize',
            'deny_label' => 'Cancel',
        ],
        'introspection' => [
            'enabled' => $introspectionEnabled,
            // This list intentionally contains only password_hash() output. The
            // plaintext resource-server secret is never an application setting.
            'clients' => $introspectionEnabled
                && is_string($introspectionClientId) && $introspectionClientId !== ''
                && is_string($introspectionSecretHash) && $introspectionSecretHash !== ''
                ? [[
                    'id' => $introspectionClientId,
                    'secret_hash' => $introspectionSecretHash,
                    'resource' => $resource,
                ]]
                : [],
        ],
    ],

    'users' => [
        'model' => config('auth.providers.users.model', User::class),
        'name_attribute' => 'name',
        'email_attribute' => 'email',
        'force_change_password_attribute' => null,
    ],
];
