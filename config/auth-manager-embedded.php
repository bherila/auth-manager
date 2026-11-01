<?php

/*
| Embedded mode: Auth Manager installed as a Composer package inside a host application
| and mounted under a path prefix. Read only by EmbeddedServiceProvider; a standalone
| deployment loads this file but never enables it. See docs/embedded-mode.md.
*/

return [
    // Everything the provider serves is below this path. No leading or trailing slash.
    'prefix' => env('AUTH_MANAGER_EMBEDDED_PREFIX', 'auth'),

    // The provider's display name; the host's APP_NAME when unset.
    'name' => env('AUTH_MANAGER_EMBEDDED_NAME'),

    // The issuer is AUTH_MANAGER_OAUTH_ISSUER, or APP_URL followed by the prefix.

    'database' => [
        // The connection the provider's tables live on; null for the host's default. A host
        // that defines database.connections.auth-manager itself replaces this pair.
        'connection' => env('AUTH_MANAGER_EMBEDDED_DB_CONNECTION'),
        'table_prefix' => env('AUTH_MANAGER_EMBEDDED_TABLE_PREFIX', 'auth_manager_'),
    ],

    'session' => [
        'cookie' => env('AUTH_MANAGER_EMBEDDED_SESSION_COOKIE', 'auth_manager_session'),
        // null for the host's session driver. The database driver uses the prefixed table.
        'driver' => env('AUTH_MANAGER_EMBEDDED_SESSION_DRIVER'),
        // Minutes; null for the host's session lifetime.
        'lifetime' => env('AUTH_MANAGER_EMBEDDED_SESSION_LIFETIME'),
    ],

    // Also publish RFC 8414 metadata at /.well-known/oauth-authorization-server/{prefix}: the
    // one path outside the prefix, which cannot collide with the host's own document.
    'well_known' => (bool) env('AUTH_MANAGER_EMBEDDED_WELL_KNOWN', true),

    // Passport's signing keys; null for storage/app/private/auth-manager/oauth.
    'keys_path' => env('AUTH_MANAGER_EMBEDDED_KEYS_PATH'),

    // Per-file overrides merged over the provider's own configuration, keyed by file name:
    // auth-manager, branding, delegated-access, application-registry,
    // application-invitations, identity-deletion and bherila-auth.
    'config' => [],
];
