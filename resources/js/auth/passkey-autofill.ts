import { authenticateWithPasskey, isAbortError, isConditionalMediationAvailable } from 'bwh-auth';

import { getCsrfToken } from './shared-components';

interface AutofillHandlers {
  onSuccess: (redirectUrl: string) => void;
}

/**
 * Conditional-mediation ("passkey autofill") owner for the login page.
 *
 * A browser allows only one pending WebAuthn request at a time, so the
 * background autofill request must be aborted before the passkey button
 * starts a modal ceremony, and before the page navigates away. Keeping a
 * single controller here lets both React islands coordinate without
 * sharing React state across roots.
 */
let controller: AbortController | null = null;
let lastHandlers: AutofillHandlers | null = null;
// Bumped by every abort so a start still awaiting the support check can be
// invalidated before it has a controller to abort.
let generation = 0;

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
}

export async function startPasskeyAutofill(handlers: AutofillHandlers): Promise<void> {
  lastHandlers = handlers;
  if (!passkeysSupported() || controller !== null) return;
  const startedIn = generation;
  if (!(await isConditionalMediationAvailable())) return;
  // The availability check is async: an abort (the button was clicked, a form
  // was submitted) or a competing start may have happened meanwhile.
  if (startedIn !== generation || controller !== null) return;

  const own = new AbortController();
  controller = own;

  try {
    const { redirectUrl } = await authenticateWithPasskey({
      endpoints: { csrfToken: getCsrfToken() },
      mediation: 'conditional',
      signal: own.signal,
    });
    handlers.onSuccess(redirectUrl || '/');
  } catch (error) {
    // A background request must never surprise the person with an error;
    // the button and the form remain available.
    if (!isAbortError(error)) {
      console.debug('Passkey autofill unavailable:', error);
    }
  } finally {
    if (controller === own) controller = null;
  }
}

export function abortPasskeyAutofill(): void {
  generation += 1;
  controller?.abort();
  controller = null;
}

export function restartPasskeyAutofill(): void {
  abortPasskeyAutofill();
  if (lastHandlers) void startPasskeyAutofill(lastHandlers);
}
