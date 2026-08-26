import { FormEvent, useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';

interface OAuthClient {
  id: string;
  name: string;
}

interface DirectoryUser {
  id: number;
  name: string;
  email: string;
  status: 'active' | 'disabled';
  roles: string[];
  disabled_at: string | null;
  last_login_date: string | null;
  client_ids: string[];
}

interface DirectoryResponse {
  users: DirectoryUser[];
  clients: OAuthClient[];
}

function errorText(error: unknown): string {
  return typeof error === 'string' ? error : error instanceof Error ? error.message : 'The request failed.';
}

function UserCard({
  user,
  clients,
  onChanged,
  onError,
}: {
  user: DirectoryUser;
  clients: OAuthClient[];
  onChanged: (message: string) => Promise<void>;
  onError: (message: string) => void;
}) {
  const [email, setEmail] = useState(user.email);
  const [password, setPassword] = useState('');
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => setEmail(user.email), [user.email]);

  async function run(action: () => Promise<unknown>, message: string): Promise<void> {
    setBusy(true);
    try {
      await action();
      await onChanged(message);
    } catch (caught) {
      onError(errorText(caught));
    } finally {
      setBusy(false);
    }
  }

  async function updateEmail(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.patch(`/api/admin/users/${user.id}/email`, { email }),
      `${user.name}'s email address was updated.`,
    );
  }

  async function resetPassword(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.put(`/api/admin/users/${user.id}/password`, {
        password,
        password_confirmation: passwordConfirmation,
      }),
      `${user.name}'s password was reset and existing sessions and tokens were revoked.`,
    );
    setPassword('');
    setPasswordConfirmation('');
  }

  async function toggleClient(client: OAuthClient, granted: boolean): Promise<void> {
    await run(
      () => granted
        ? fetchWrapper.delete(`/api/admin/users/${user.id}/clients/${client.id}`, {})
        : fetchWrapper.put(`/api/admin/users/${user.id}/clients/${client.id}`, {}),
      `${client.name} access was ${granted ? 'removed' : 'granted'}.`,
    );
  }

  async function deletePerson(): Promise<void> {
    const confirmed = window.confirm(
      `Delete ${user.name}? Sign-in and tokens stop immediately. Connected applications reconcile independently, and the provider record is retained temporarily. This cannot be undone from this screen.`,
    );

    if (!confirmed) {
      return;
    }

    await run(
      () => fetchWrapper.delete(`/api/admin/users/${user.id}`, {}),
      `${user.name} was deleted at the provider and queued for application reconciliation.`,
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>{user.name}</CardTitle>
            <CardDescription>Directory subject {user.id} · {user.roles.join(', ') || 'no sign-in role'}</CardDescription>
          </div>
          <span
            className={
              user.status === 'active'
                ? 'rounded-full bg-success/15 px-3 py-1 text-xs font-semibold text-success'
                : 'rounded-full bg-destructive/15 px-3 py-1 text-xs font-semibold text-destructive'
            }
          >
            {user.status === 'active' ? 'Active' : 'Disabled'}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <form className="grid gap-3 sm:grid-cols-[1fr_auto]" onSubmit={(event) => void updateEmail(event)}>
          <div className="space-y-2">
            <Label htmlFor={`email-${user.id}`}>Email address</Label>
            <Input
              id={`email-${user.id}`}
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </div>
          <Button className="self-end" type="submit" variant="outline" disabled={busy || email === user.email}>
            Save email
          </Button>
        </form>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Application grants</legend>
          <p className="text-muted-foreground text-xs">
            A grant allows this person to request a token. It does not create their account or permissions in that application.
          </p>
          {clients.length === 0 ? (
            <p className="text-muted-foreground text-sm">No active OAuth applications are registered.</p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {clients.map((client) => {
                const granted = user.client_ids.includes(client.id);

                return (
                  <label className="border-border flex items-center gap-3 rounded-md border p-3 text-sm" key={client.id}>
                    <input
                      type="checkbox"
                      checked={granted}
                      disabled={busy}
                      onChange={() => void toggleClient(client, granted)}
                    />
                    {client.name}
                  </label>
                );
              })}
            </div>
          )}
        </fieldset>

        <form className="grid gap-3 sm:grid-cols-2" onSubmit={(event) => void resetPassword(event)}>
          <div className="space-y-2">
            <Label htmlFor={`password-${user.id}`}>New password</Label>
            <Input
              id={`password-${user.id}`}
              type="password"
              minLength={12}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`password-confirmation-${user.id}`}>Confirm password</Label>
            <Input
              id={`password-confirmation-${user.id}`}
              type="password"
              minLength={12}
              value={passwordConfirmation}
              onChange={(event) => setPasswordConfirmation(event.target.value)}
              required
            />
          </div>
          <Button type="submit" variant="outline" disabled={busy || password.length < 12}>
            Reset password
          </Button>
        </form>

        <div className="border-border flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="text-muted-foreground text-xs">
            {user.last_login_date ? `Last sign-in: ${new Date(user.last_login_date).toLocaleString()}` : 'No recorded sign-in'}
          </p>
          {user.status === 'active' ? (
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => void run(
                () => fetchWrapper.post(`/api/admin/users/${user.id}/disable`, {}),
                `${user.name} was disabled and existing sessions and tokens were revoked.`,
              )}
            >
              Disable person
            </Button>
          ) : (
            <Button
              type="button"
              disabled={busy}
              onClick={() => void run(
                () => fetchWrapper.post(`/api/admin/users/${user.id}/enable`, {}),
                `${user.name} was re-enabled.`,
              )}
            >
              Re-enable person
            </Button>
          )}
        </div>
        <div className="border-destructive/40 flex flex-wrap items-center justify-between gap-3 rounded-md border p-4">
          <p className="text-muted-foreground max-w-2xl text-xs">
            Deletion stops provider sign-in immediately. Connected applications remove their own local records through reconciliation.
          </p>
          <Button type="button" variant="destructive" disabled={busy} onClick={() => void deletePerson()}>
            Delete person
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function DirectoryAdminPage() {
  const [data, setData] = useState<DirectoryResponse>({ users: [], clients: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [clientIds, setClientIds] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    const response = await fetchWrapper.get('/api/admin/users') as DirectoryResponse;
    setData(response);
  }, []);

  useEffect(() => {
    void load()
      .catch((caught) => setError(errorText(caught)))
      .finally(() => setLoading(false));
  }, [load]);

  async function changed(nextMessage: string): Promise<void> {
    setError(null);
    setMessage(nextMessage);
    try {
      await load();
    } catch (caught) {
      setError(errorText(caught));
    }
  }

  async function createUser(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreating(true);
    setError(null);
    setMessage(null);

    try {
      await fetchWrapper.post('/api/admin/users', {
        name,
        email,
        password,
        password_confirmation: passwordConfirmation,
        enabled,
        client_ids: clientIds,
      });
      setName('');
      setEmail('');
      setPassword('');
      setPasswordConfirmation('');
      setClientIds([]);
      await changed('The provider account was created. Connected applications still decide whether to create a local account.');
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setCreating(false);
    }
  }

  if (loading) {
    return <main className="mx-auto max-w-6xl px-4 py-10">Loading directory…</main>;
  }

  return (
    <main className="mx-auto max-w-6xl space-y-8 px-4 py-10">
      <header>
        <p className="text-primary text-sm font-semibold">Identity provider</p>
        <h1 className="text-3xl font-bold tracking-tight">Directory administration</h1>
        <p className="text-muted-foreground mt-2 max-w-3xl">
          Manage provider sign-in, credentials, and coarse application grants here. Each connected application owns its own accounts and permissions.
        </p>
      </header>

      {error ? <p className="border-destructive bg-destructive/10 text-destructive rounded-md border p-3 text-sm">{error}</p> : null}
      {message ? <p className="border-success bg-success/10 text-success rounded-md border p-3 text-sm">{message}</p> : null}

      <Card>
        <CardHeader>
          <CardTitle>Create a person</CardTitle>
          <CardDescription>
            This creates only the provider account. A selected grant permits OAuth, but never creates a record inside a connected application.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-5" onSubmit={(event) => void createUser(event)}>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="new-name">Name</Label>
                <Input id="new-name" value={name} onChange={(event) => setName(event.target.value)} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-email">Email address</Label>
                <Input id="new-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">Temporary password</Label>
                <Input
                  id="new-password"
                  type="password"
                  minLength={12}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password-confirmation">Confirm password</Label>
                <Input
                  id="new-password-confirmation"
                  type="password"
                  minLength={12}
                  value={passwordConfirmation}
                  onChange={(event) => setPasswordConfirmation(event.target.value)}
                  required
                />
              </div>
            </div>
            <label className="flex items-center gap-3 text-sm">
              <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />
              Enable provider sign-in immediately
            </label>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">Initial application grants</legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {data.clients.map((client) => (
                  <label className="border-border flex items-center gap-3 rounded-md border p-3 text-sm" key={client.id}>
                    <input
                      type="checkbox"
                      checked={clientIds.includes(client.id)}
                      onChange={(event) => setClientIds((current) => event.target.checked
                        ? [...current, client.id]
                        : current.filter((id) => id !== client.id))}
                    />
                    {client.name}
                  </label>
                ))}
              </div>
            </fieldset>
            <Button type="submit" disabled={creating || password.length < 12}>
              {creating ? 'Creating…' : 'Create provider account'}
            </Button>
          </form>
        </CardContent>
      </Card>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold">People</h2>
        {data.users.length === 0 ? (
          <p className="text-muted-foreground">No provider accounts exist.</p>
        ) : data.users.map((user) => (
          <UserCard
            key={user.id}
            user={user}
            clients={data.clients}
            onChanged={changed}
            onError={(nextError) => {
              setMessage(null);
              setError(nextError);
            }}
          />
        ))}
      </section>
    </main>
  );
}

const mount = document.getElementById('directory-admin-mount');
if (mount) {
  createRoot(mount).render(<DirectoryAdminPage />);
}
