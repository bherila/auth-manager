import { TwoFactorForm } from 'bwh-auth';
import React, { useState } from 'react';

import { Button } from '@/components/ui/button';
import { fetchWrapper } from '@/fetchWrapper';

import { getAuthComponents, getCsrfToken } from './shared-components';

interface EmailCodeResponse {
  success?: boolean;
  attempt_token?: string;
  message?: string;
}

export function passwordlessLoginDestination(redirect: string | null | undefined): string {
  return redirect ?? '/dashboard';
}

/**
 * Passwordless email-code sign in. Requests a one-time code, then reuses the
 * bherila-auth TwoFactorForm to verify it. The request step always advances to
 * code entry (even for unknown emails) so it can't be used to enumerate accounts.
 */
export function PasswordlessLogin(): React.JSX.Element {
  const [email, setEmail] = useState('');
  const [remember, setRemember] = useState(false);
  const [attemptToken, setAttemptToken] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function requestCode(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const result = (await fetchWrapper.post('/login/email-code', { email, remember })) as EmailCodeResponse;
      setAttemptToken(result.attempt_token ?? '');
    } catch {
      setError('Could not send a sign-in code. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  if (attemptToken !== null) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          We sent a sign-in code to <span className="font-medium text-foreground">{email}</span> if it matches an
          account. Enter it below.
        </p>
        <TwoFactorForm
          components={getAuthComponents()}
          attemptToken={attemptToken}
          endpoints={{ csrfToken: getCsrfToken() }}
          onSuccess={(result) => {
            window.location.href = passwordlessLoginDestination(result.redirect);
          }}
          onError={setError}
        />
        <button
          type="button"
          onClick={() => {
            setAttemptToken(null);
            setError('');
          }}
          className="text-sm text-muted-foreground underline hover:text-foreground"
        >
          Use a different email
        </button>
        {error && <p className="text-destructive text-sm">{error}</p>}
      </div>
    );
  }

  return (
    <form onSubmit={requestCode} className="space-y-3">
      <div>
        <label htmlFor="passwordless-email" className="block text-sm font-semibold text-foreground mb-1">
          Email
        </label>
        <input
          type="email"
          id="passwordless-email"
          name="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
          autoComplete="email"
          className="block w-full px-3 py-2 bg-muted border border-input rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-ring transition-colors"
        />
      </div>
      <div className="flex items-center">
        <input
          type="checkbox"
          id="passwordless-remember"
          checked={remember}
          onChange={(event) => setRemember(event.target.checked)}
          className="h-4 w-4 rounded border-input text-blue-600 focus:ring-ring"
        />
        <label htmlFor="passwordless-remember" className="ml-2 block text-sm text-foreground">
          Keep me logged in
        </label>
      </div>
      <Button type="submit" variant="outline" className="w-full" disabled={submitting}>
        {submitting ? 'Sending code…' : 'Email me a sign-in code'}
      </Button>
      {error && <p className="text-destructive text-sm">{error}</p>}
    </form>
  );
}
