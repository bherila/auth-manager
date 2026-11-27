import type { AuthEndpointConfig } from 'bwh-auth';

/**
 * The provider's base path: '' at the root of its own deployment, '/auth' (by default)
 * when it is embedded in a host application. Rendered by layouts/app.blade.php, so one
 * build serves either mode.
 */
export function basePath(): string {
  const base = document.querySelector('meta[name="auth-manager-base"]')?.getAttribute('content') ?? '/';

  return base.replace(/\/+$/, '');
}

/** A root-relative provider URL: appPath('/api/admin/users') is '/auth/api/admin/users' when embedded. */
export function appPath(path: string): string {
  const relative = path.startsWith('/') ? path : `/${path}`;

  return relative === '/' ? `${basePath()}/` : `${basePath()}${relative}`;
}

/** auth-laravel's passkey and two-factor endpoints, below this provider's base path. */
export function authEndpoints(csrfToken: string, relatedRp?: string): AuthEndpointConfig {
  return {
    csrfToken,
    changePassword: appPath('/api/change-password'),
    confirmPassword: appPath('/api/auth/confirm-password'),
    passkeyConfirmOptions: appPath('/api/passkeys/confirm/options'),
    passkeyConfirm: appPath('/api/passkeys/confirm'),
    twoFactorVerify: appPath('/api/auth/two-factor/verify'),
    twoFactorResend: appPath('/api/auth/two-factor/resend'),
    passkeyList: appPath('/api/passkeys'),
    passkeyRegisterOptions: appPath('/api/passkeys/register/options'),
    passkeyRegister: appPath('/api/passkeys/register'),
    passkeyDelete: (id) => appPath(`/api/passkeys/${encodeURIComponent(String(id))}`),
    passkeyAuthOptions: appPath('/api/passkeys/auth/options') + (relatedRp ? `?rp_id=${encodeURIComponent(relatedRp)}` : ''),
    passkeyAuth: appPath('/api/passkeys/auth'),
  };
}
