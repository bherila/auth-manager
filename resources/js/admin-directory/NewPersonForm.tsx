import { FormEvent, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';
import { appPath } from '@/lib/app-path';

import type { DirectoryUser, OAuthClient } from './types';
import { errorText, passwordMinLength } from './types';

interface NewPersonFormProps {
  clients: OAuthClient[];
  onCreated: (user: DirectoryUser, message: string) => Promise<void>;
  onError: (message: string) => void;
}

export function NewPersonForm({ clients, onCreated, onError }: NewPersonFormProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [clientIds, setClientIds] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreating(true);
    try {
      const response = await fetchWrapper.post(appPath('/api/admin/users'), {
        name, email, password, password_confirmation: passwordConfirmation, enabled, client_ids: clientIds,
      }) as { user: DirectoryUser };
      setName('');
      setEmail('');
      setPassword('');
      setPasswordConfirmation('');
      setClientIds([]);
      await onCreated(response.user, 'The provider account was created. Connected applications still decide whether to create a local account.');
    } catch (caught) {
      onError(errorText(caught));
    } finally {
      setCreating(false);
    }
  }

  return (
    <form className="max-w-2xl space-y-4" onSubmit={(event) => void create(event)}>
      <p className="text-muted-foreground text-sm">
        This creates only the provider account. A selected grant permits OAuth, but never creates a record inside a connected application.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="new-name">Name</Label>
          <Input id="new-name" value={name} maxLength={255} onChange={(event) => setName(event.target.value)} required />
        </div>
        <div className="space-y-1">
          <Label htmlFor="new-email">Email</Label>
          <Input id="new-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
        </div>
        <div className="space-y-1">
          <Label htmlFor="new-password">Temporary password</Label>
          <Input id="new-password" type="password" autoComplete="new-password" minLength={passwordMinLength} value={password}
            onChange={(event) => setPassword(event.target.value)} required />
        </div>
        <div className="space-y-1">
          <Label htmlFor="new-password-confirmation">Confirm password</Label>
          <Input id="new-password-confirmation" type="password" autoComplete="new-password" minLength={passwordMinLength} value={passwordConfirmation}
            onChange={(event) => setPasswordConfirmation(event.target.value)} required />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
        Enable provider sign-in immediately
      </label>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Initial application grants</legend>
        <div className="grid gap-1 sm:grid-cols-2">
          {clients.map((client) => (
            <label className="hover:bg-accent flex items-center gap-2 rounded-md p-2 text-sm" key={client.id}>
              <input type="checkbox" checked={clientIds.includes(client.id)}
                onChange={(event) => setClientIds((current) => event.target.checked ? [...current, client.id] : current.filter((id) => id !== client.id))} />
              {client.name}
            </label>
          ))}
        </div>
      </fieldset>
      <Button type="submit" disabled={creating || password.length < passwordMinLength}>{creating ? 'Creating…' : 'Create provider account'}</Button>
    </form>
  );
}
