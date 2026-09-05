/**
 * Element ids shared between resources/views/login.blade.php and the React
 * islands that enhance it. The Blade page owns these nodes; the islands only
 * read them or toggle `hidden` / `aria-*` attributes on them.
 */
export const LOGIN_DOM = {
  passwordSection: 'password-login',
  passwordForm: 'password-login-form',
  emailInput: 'email',
  passwordInput: 'password',
  rememberInput: 'remember',
  passwordToggle: 'password-toggle',
  forgotPassword: 'forgot-password',
  serverError: 'login-error',
  passkeyMount: 'passkey-login-mount',
  emailCodeMount: 'email-code-login-mount',
} as const;

/** Look an element up at event time so a missing node degrades to a no-op. */
export function loginEl<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}
