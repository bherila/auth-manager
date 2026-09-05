import { isAbortError } from 'bwh-auth';

const CONNECTION_MESSAGE = "We couldn't reach the server. Check your connection and try again.";
const DISABLED_MESSAGE = 'Your account is disabled. Please contact an administrator.';
const SESSION_MESSAGE = 'Your session expired. Reload the page and try again.';

function messageOf(error: unknown): string {
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message;
  return '';
}

/** Cancelled or timed-out WebAuthn ceremonies are not errors worth showing. */
export function isPasskeyCancellation(error: unknown): boolean {
  return isAbortError(error) || (error instanceof DOMException && error.name === 'NotAllowedError');
}

/**
 * Translate whatever `authenticateWithPasskey` throws into copy a person can
 * act on. The server collapses every failure into "Authentication failed: …"
 * with the raw exception text appended, so match on fragments.
 */
export function mapPasskeyError(error: unknown): string {
  if (error instanceof DOMException) {
    if (error.name === 'InvalidStateError') return "That device doesn't have a passkey for this site.";
    if (error.name === 'SecurityError') return "Passkeys can't be used on this address. Sign in with your email below.";
  }
  if (error instanceof TypeError) return CONNECTION_MESSAGE;

  const message = messageOf(error).toLowerCase();
  if (message.includes('no pending authentication options')) return 'Your passkey request expired. Try again.';
  if (message.includes('not active') || message.includes('not allowed to log in') || message.includes('disabled')) {
    return DISABLED_MESSAGE;
  }
  if (message.includes('csrf') || message.includes('419')) return SESSION_MESSAGE;

  return "We couldn't verify that passkey. Try again, or sign in with your email below.";
}

export const CODE_LOCKED_MESSAGE = 'Too many incorrect codes. Send a new code to continue.';

/**
 * Translate a verify/request failure (the backend `message` string that
 * fetchWrapper rejects with, or a thrown Error) into user-facing copy. An
 * incorrect code and an invalid attempt share one message so the page never
 * reveals whether the address belongs to an account.
 */
export function mapCodeError(error: unknown): string {
  if (error instanceof TypeError) return CONNECTION_MESSAGE;

  const message = messageOf(error).toLowerCase();
  if (message.includes('too many')) return CODE_LOCKED_MESSAGE;
  if (message.includes('incorrect') || message.includes('invalid or expired') || message.includes('log in again')) {
    return "That code isn't correct or has expired. Check it and try again, or send a new code.";
  }
  if (message.includes('not active') || message.includes('disabled')) return DISABLED_MESSAGE;
  if (message.includes('csrf') || message.includes('419')) return SESSION_MESSAGE;
  if (message.includes('email')) return 'Enter a valid email address.';

  return 'Something went wrong. Please try again.';
}
