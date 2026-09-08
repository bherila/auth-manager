import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { getCsrfToken } from '@/auth/shared-components';

interface Props { passwordUrl: string; loginUrl: string }
interface PasswordResponse { success?: boolean; message?: string; errors?: Record<string, string[]> }

function AccountSettings({ passwordUrl, loginUrl }: Props): React.JSX.Element {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: React.SubmitEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(true);
    setError('');
    try {
      const fields = Object.fromEntries(new FormData(form));
      const response = await fetch(passwordUrl, {
        method: 'PUT', credentials: 'same-origin',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': getCsrfToken() },
        body: JSON.stringify(fields),
      });
      const data = await response.json() as PasswordResponse;
      if (!response.ok || data.success !== true) throw new Error(data.errors ? Object.values(data.errors).flat().join(' ') : data.message || 'Unable to change password. Please sign in again and retry.');
      form.reset();
      setDone(true);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Unable to change password. Please try again.');
    } finally { setBusy(false); }
  }
  if (done) return <div className="mt-4"><p role="status">Password changed. You have been signed out.</p><a className="mt-3 inline-block underline" href={loginUrl}>Sign in with your new password</a></div>;
  return <form onSubmit={submit} className="mt-4 space-y-4">
    {error ? <p role="alert" className="text-destructive text-sm">{error}</p> : null}
    {([{ name: 'current_password', label: 'Current password', autocomplete: 'current-password' }, { name: 'password', label: 'New password (12–72 characters)', autocomplete: 'new-password' }, { name: 'password_confirmation', label: 'Confirm new password', autocomplete: 'new-password' }]).map(field => <div key={field.name}><label htmlFor={field.name} className="mb-1 block text-sm font-medium">{field.label}</label><input id={field.name} name={field.name} type="password" autoComplete={field.autocomplete} required minLength={field.name === 'current_password' ? undefined : 12} maxLength={field.name === 'current_password' ? 1024 : 72} disabled={busy} className="w-full rounded-md border border-border bg-background px-3 py-2 focus:outline-2 focus:outline-ring" /></div>)}
    <button disabled={busy} type="submit" className="rounded-md bg-primary px-4 py-2 text-primary-foreground disabled:opacity-50">{busy ? 'Changing password…' : 'Change password and sign out'}</button>
  </form>;
}
const mount = document.getElementById('account-settings-mount');
if (mount?.dataset.passwordUrl && mount.dataset.loginUrl) createRoot(mount).render(<AccountSettings passwordUrl={mount.dataset.passwordUrl} loginUrl={mount.dataset.loginUrl} />);
