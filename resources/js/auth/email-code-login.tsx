import { Mail } from 'lucide-react';
import React, { useCallback, useEffect, useRef, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';

import { LOGIN_DOM, loginEl } from './login-dom';
import { CODE_LOCKED_MESSAGE, mapCodeError } from './login-errors';
import { abortPasskeyAutofill, restartPasskeyAutofill } from './passkey-autofill';

interface EmailCodeResponse {
  success?: boolean;
  attempt_token?: string;
}

interface VerifyResponse {
  success?: boolean;
  redirect?: string;
}

const CODE_INPUT_ID = 'email-code';
const HINT_ID = 'email-code-hint';
const ERROR_ID = 'email-code-error';
const RESEND_COOLDOWN_SECONDS = 30;

/** Request a code for `email`. The server always answers 200 so unknown addresses are indistinguishable. */
async function requestSignInCode(email: string, remember: boolean): Promise<string> {
  const result = (await fetchWrapper.post('/login/email-code', { email, remember })) as EmailCodeResponse;
  return result.attempt_token ?? '';
}

function setPasswordSectionHidden(hidden: boolean): void {
  const section = loginEl(LOGIN_DOM.passwordSection);
  if (section) section.hidden = hidden;
}

/**
 * Emailed one-time code sign-in. Starts as a single secondary button that
 * reads the email already typed into the password form, then replaces that
 * form in place with the code-entry step.
 */
export function EmailCodeLogin(): React.JSX.Element {
  const [step, setStep] = useState<'idle' | 'requesting' | 'code'>('idle');
  const [email, setEmail] = useState('');
  const [remember, setRemember] = useState(false);
  const [attemptToken, setAttemptToken] = useState('');
  const [code, setCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);
  const [locked, setLocked] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState('');
  const [cooldown, setCooldown] = useState(0);
  const codeInputRef = useRef<HTMLInputElement>(null);
  // Bumped when leaving the code step so a verify or resend response that
  // arrives afterwards is ignored instead of redirecting or writing a stale error.
  const codeSessionRef = useRef(0);

  const clearEmailFieldError = useCallback((field: HTMLInputElement) => {
    field.removeAttribute('aria-invalid');
    const described = (field.getAttribute('aria-describedby') ?? '')
      .split(/\s+/)
      .filter((id) => id !== '' && id !== ERROR_ID);
    if (described.length > 0) field.setAttribute('aria-describedby', described.join(' '));
    else field.removeAttribute('aria-describedby');
  }, []);

  const requestCode = useCallback(async () => {
    const field = loginEl<HTMLInputElement>(LOGIN_DOM.emailInput);
    const address = field?.value.trim() ?? '';
    if (!field || address === '' || !field.checkValidity()) {
      setError(address === '' ? 'Enter your email address above first.' : 'Enter a valid email address above first.');
      if (field) {
        field.setAttribute('aria-invalid', 'true');
        const described = (field.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean);
        if (!described.includes(ERROR_ID)) field.setAttribute('aria-describedby', [...described, ERROR_ID].join(' '));
        field.addEventListener('input', () => clearEmailFieldError(field), { once: true });
        field.focus();
      }
      return;
    }

    clearEmailFieldError(field);
    const keep = loginEl<HTMLInputElement>(LOGIN_DOM.rememberInput)?.checked ?? false;
    setError(null);
    setStep('requesting');
    abortPasskeyAutofill();
    try {
      const token = await requestSignInCode(address, keep);
      setEmail(address);
      setRemember(keep);
      setAttemptToken(token);
      setCode('');
      setLocked(false);
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setStatus('Code sent.');
      setPasswordSectionHidden(true);
      setStep('code');
    } catch (caught) {
      setError(mapCodeError(caught));
      setStep('idle');
      restartPasskeyAutofill();
    }
  }, [clearEmailFieldError]);

  // "Forgot password?" in the Blade form triggers the same flow.
  useEffect(() => {
    const forgot = loginEl<HTMLButtonElement>(LOGIN_DOM.forgotPassword);
    if (!forgot) return undefined;
    const onClick = (): void => void requestCode();
    forgot.addEventListener('click', onClick);
    forgot.hidden = false;
    return () => forgot.removeEventListener('click', onClick);
  }, [requestCode]);

  useEffect(() => {
    if (step === 'code') codeInputRef.current?.focus();
  }, [step]);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const timer = window.setTimeout(() => setCooldown((seconds) => seconds - 1), 1000);
    return () => window.clearTimeout(timer);
  }, [cooldown]);

  async function verify(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from your email.');
      codeInputRef.current?.focus();
      return;
    }
    setError(null);
    setStatus('');
    setVerifying(true);
    const session = codeSessionRef.current;
    try {
      const result = (await fetchWrapper.post('/api/auth/two-factor/verify', {
        attempt_token: attemptToken,
        code,
      })) as VerifyResponse;
      if (session !== codeSessionRef.current) return;
      window.location.assign(result.redirect || '/');
    } catch (caught) {
      if (session !== codeSessionRef.current) return;
      const message = mapCodeError(caught);
      setError(message);
      if (message === CODE_LOCKED_MESSAGE) setLocked(true);
      setCode('');
      setVerifying(false);
      codeInputRef.current?.focus();
    }
  }

  // A fresh request rather than the package's resend endpoint: resend fails
  // for the empty token unknown addresses receive, which would reveal whether
  // an account exists. Re-requesting is always 200 and rotates the token.
  async function resend(): Promise<void> {
    if (resending) return;
    setError(null);
    setStatus('');
    setResending(true);
    const session = codeSessionRef.current;
    try {
      const token = await requestSignInCode(email, remember);
      if (session !== codeSessionRef.current) return;
      setAttemptToken(token);
      setCode('');
      setLocked(false);
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setStatus('We sent a new code.');
      codeInputRef.current?.focus();
    } catch (caught) {
      if (session !== codeSessionRef.current) return;
      setError(mapCodeError(caught));
    } finally {
      if (session === codeSessionRef.current) setResending(false);
    }
  }

  function back(): void {
    codeSessionRef.current += 1;
    setVerifying(false);
    setResending(false);
    setStep('idle');
    setError(null);
    setStatus('');
    setCode('');
    setLocked(false);
    setPasswordSectionHidden(false);
    loginEl<HTMLInputElement>(LOGIN_DOM.emailInput)?.focus();
    restartPasskeyAutofill();
  }

  if (step !== 'code') {
    const requesting = step === 'requesting';
    return (
      <div>
        <Button
          type="button"
          variant="ghost"
          size="lg"
          className="w-full"
          onClick={() => void requestCode()}
          disabled={requesting}
          aria-busy={requesting}
          aria-describedby={error ? ERROR_ID : undefined}
        >
          <Mail aria-hidden="true" />
          {requesting ? 'Sending your code…' : 'Email me a sign-in code instead'}
        </Button>
        {error ? (
          <p id={ERROR_ID} role="alert" className="text-destructive mt-2 text-sm">
            {error}
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Check your email</h2>
        <p id={HINT_ID} className="text-muted-foreground mt-1 text-sm">
          If <strong className="text-foreground font-medium">{email}</strong> belongs to an account, we sent it a
          6-digit code. It expires in 15 minutes.
        </p>
      </div>

      <form onSubmit={(event) => void verify(event)} noValidate className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor={CODE_INPUT_ID}>Verification code</Label>
          <Input
            ref={codeInputRef}
            id={CODE_INPUT_ID}
            name="code"
            type="text"
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            autoComplete="one-time-code"
            required
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
            aria-describedby={`${HINT_ID} ${ERROR_ID}`}
            aria-invalid={error ? true : undefined}
            className="h-10 text-center text-lg tracking-[0.3em]"
          />
        </div>
        <Button type="submit" size="lg" className="w-full" disabled={verifying || locked} aria-busy={verifying}>
          {verifying ? 'Verifying…' : 'Verify and sign in'}
        </Button>
      </form>

      {/* Both regions are always rendered so assistive technology announces changes. */}
      <p id={ERROR_ID} role="alert" className="text-destructive text-sm empty:hidden">
        {error}
      </p>
      <p aria-live="polite" className="text-muted-foreground text-sm empty:hidden">
        {status}
      </p>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <Button
          type="button"
          variant="outline"
          onClick={() => void resend()}
          disabled={cooldown > 0 || resending || verifying}
          aria-busy={resending}
        >
          {resending ? 'Sending…' : cooldown > 0 ? `Send a new code (${cooldown}s)` : 'Send a new code'}
        </Button>
        <Button type="button" variant="link" onClick={back} disabled={verifying || resending}>
          Use a different email
        </Button>
      </div>
    </div>
  );
}
