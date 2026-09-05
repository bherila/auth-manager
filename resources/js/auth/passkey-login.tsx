import { authenticateWithPasskey } from 'bwh-auth';
import { KeyRound } from 'lucide-react';
import React, { useCallback, useEffect, useState } from 'react';

import { Button } from '@/components/ui/button';

import { LOGIN_DOM, loginEl } from './login-dom';
import { isPasskeyCancellation, mapPasskeyError } from './login-errors';
import {
  abortPasskeyAutofill,
  passkeysSupported,
  restartPasskeyAutofill,
  startPasskeyAutofill,
} from './passkey-autofill';
import { getCsrfToken } from './shared-components';

const ERROR_ID = 'passkey-error';

function go(redirectUrl: string): void {
  window.location.assign(redirectUrl || '/');
}

/**
 * Passkey sign-in: a visible button plus browser autofill (conditional
 * mediation) armed on load. The same server endpoints are used either way,
 * so the session freshness stamp for passkey management keeps working.
 */
export function PasskeyLogin(): React.JSX.Element {
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const supported = passkeysSupported();

  useEffect(() => {
    if (!supported) return undefined;

    void startPasskeyAutofill({ onSuccess: go });

    // The page is about to navigate; a pending WebAuthn request would only
    // linger and block the next page's own ceremony.
    const form = loginEl<HTMLFormElement>(LOGIN_DOM.passwordForm);
    const onSubmit = (): void => abortPasskeyAutofill();
    form?.addEventListener('submit', onSubmit);

    return () => {
      form?.removeEventListener('submit', onSubmit);
      abortPasskeyAutofill();
    };
  }, [supported]);

  const signIn = useCallback(async () => {
    setError(null);
    setVerifying(true);
    abortPasskeyAutofill();
    try {
      const { redirectUrl } = await authenticateWithPasskey({ endpoints: { csrfToken: getCsrfToken() } });
      go(redirectUrl);
    } catch (caught) {
      if (!isPasskeyCancellation(caught)) {
        setError(mapPasskeyError(caught));
      }
      setVerifying(false);
      restartPasskeyAutofill();
    }
  }, []);

  if (!supported) {
    return (
      <p className="text-muted-foreground text-sm">
        Passkeys aren&rsquo;t available in this browser. Sign in with your email below.
      </p>
    );
  }

  return (
    <div>
      <Button
        type="button"
        variant="outline"
        size="lg"
        className="w-full"
        onClick={() => void signIn()}
        disabled={verifying}
        aria-busy={verifying}
        aria-describedby={error ? ERROR_ID : undefined}
      >
        <KeyRound aria-hidden="true" />
        {verifying ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
      </Button>
      {error ? (
        <p id={ERROR_ID} role="alert" className="text-destructive mt-2 text-sm">
          {error}
        </p>
      ) : null}
    </div>
  );
}
