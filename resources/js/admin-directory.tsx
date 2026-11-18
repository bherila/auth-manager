import { FormEvent, useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';
import { appPath } from '@/lib/app-path';

const passwordMinLength = Number(document.getElementById('directory-admin-mount')?.dataset.passwordMinLength);

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
  administration_revision: string;
  disabled_at: string | null;
  last_login_date: string | null;
  client_ids: string[];
  direct_client_ids: string[];
  group_ids: number[];
}

interface DirectoryResponse {
  users: DirectoryUser[];
  clients: OAuthClient[];
}

interface AccessGroup {
  id: number;
  name: string;
  description: string | null;
  member_ids: number[];
  client_ids: string[];
}

interface GroupsResponse {
  groups: AccessGroup[];
}

function errorText(error: unknown): string {
  return typeof error === 'string' ? error : error instanceof Error ? error.message : 'The request failed.';
}

function UserCard({
  user,
  clients,
  groups,
  onChanged,
  onError,
}: {
  user: DirectoryUser;
  clients: OAuthClient[];
  groups: AccessGroup[];
  onChanged: (message: string) => Promise<void>;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState(user.name);
  const [email, setEmail] = useState(user.email);
  const [password, setPassword] = useState('');
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => setName(user.name), [user.name]);
  useEffect(() => setEmail(user.email), [user.email]);

  async function run(action: () => Promise<unknown>, message: string): Promise<void> {
    setBusy(true);
    try {
      const result = await action();
      if (typeof result === 'object' && result !== null && 'redirect' in result && typeof result.redirect === 'string') {
        window.location.assign(result.redirect);
        return;
      }
      await onChanged(message);
    } catch (caught) {
      onError(errorText(caught));
    } finally {
      setBusy(false);
    }
  }

  async function updateName(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.patch(appPath(`/api/admin/users/${user.id}/name`), { name }),
      'Provider display name was updated.',
    );
  }

  async function updateEmail(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.patch(appPath(`/api/admin/users/${user.id}/email`), { email }),
      `${user.name}'s email address was updated.`,
    );
  }

  async function resetPassword(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.put(appPath(`/api/admin/users/${user.id}/password`), {
        password,
        password_confirmation: passwordConfirmation,
      }),
      `${user.name}'s password was reset and existing sessions and tokens were revoked.`,
    );
    setPassword('');
    setPasswordConfirmation('');
  }

  async function toggleClient(client: OAuthClient, direct: boolean, throughGroups: string[]): Promise<void> {
    const remaining = throughGroups.length > 0 ? ` ${user.name} keeps access through ${throughGroups.join(', ')}.` : '';
    await run(
      () => direct
        ? fetchWrapper.delete(appPath(`/api/admin/users/${user.id}/clients/${client.id}`), {})
        : fetchWrapper.put(appPath(`/api/admin/users/${user.id}/clients/${client.id}`), {}),
      `${client.name} direct grant was ${direct ? `removed.${remaining}` : 'added.'} Application permissions are managed separately.`,
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
      () => fetchWrapper.delete(appPath(`/api/admin/users/${user.id}`), { expected_revision: user.administration_revision }),
      `${user.name} was deleted at the provider and queued for application reconciliation.`,
    );
  }

  async function changeAdministrator(): Promise<void> {
    const administrator = !user.roles.includes('admin');
    if (!window.confirm(
      `${administrator ? 'Grant' : 'Remove'} provider administrator authority ${administrator ? 'for' : 'from'} ${user.name}? This controls this identity directory and credentials; application permissions stay separate. Their existing sessions will end.`,
    )) return;
    await run(
      () => fetchWrapper.put(appPath(`/api/admin/users/${user.id}/provider-administrator`), {
        administrator,
        expected_revision: user.administration_revision,
      }),
      `${user.name}'s provider administrator authority was ${administrator ? 'granted' : 'removed'}.`,
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle>{user.name}</CardTitle>
            <CardDescription>Directory subject {user.id} · Provider roles: {user.roles.join(', ') || 'no sign-in role'}</CardDescription>
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
        <fieldset className="border-border space-y-2 rounded-md border p-4">
          <legend className="px-1 text-sm font-medium">Provider administrator authority</legend>
          <p className="text-muted-foreground text-xs">Controls people and credentials in this provider. OAuth grants and application administrator permissions are separate.</p>
          <Button type="button" variant={user.roles.includes('admin') ? 'destructive' : 'outline'}
            disabled={busy || (!user.roles.includes('admin') && user.status !== 'active')}
            onClick={() => void changeAdministrator()}>
            {user.roles.includes('admin') ? 'Remove provider administrator' : 'Grant provider administrator'}
          </Button>
        </fieldset>
        <form className="grid gap-3 sm:grid-cols-[1fr_auto]" onSubmit={(event) => void updateName(event)}>
          <div className="space-y-2">
            <Label htmlFor={`name-${user.id}`}>Provider display name</Label>
            <Input
              id={`name-${user.id}`}
              value={name}
              maxLength={255}
              onChange={(event) => setName(event.target.value)}
              required
            />
            <p className="text-muted-foreground text-xs">
              This is the name shown in the identity directory. Applications may use their own nickname.
            </p>
          </div>
          <Button className="self-end" type="submit" variant="outline" disabled={busy || name.trim() === '' || name === user.name}>
            Save name
          </Button>
        </form>
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
          <legend className="text-sm font-medium">OAuth client grants</legend>
          <p className="text-muted-foreground text-xs">
            A grant allows this person to request a token. It does not create their account or permissions in that application.
            A checked box is a direct grant; access through a group is shown beside it and is changed in Groups.
          </p>
          {clients.length === 0 ? (
            <p className="text-muted-foreground text-sm">No active OAuth applications are registered.</p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {clients.map((client) => {
                const direct = user.direct_client_ids.includes(client.id);
                const throughGroups = groups
                  .filter((group) => user.group_ids.includes(group.id) && group.client_ids.includes(client.id))
                  .map((group) => group.name);

                return (
                  <label className="border-border flex items-center gap-3 rounded-md border p-3 text-sm" key={client.id}>
                    <input
                      type="checkbox"
                      checked={direct}
                      disabled={busy}
                      onChange={() => void toggleClient(client, direct, throughGroups)}
                    />
                    <span>
                      {client.name}
                      {throughGroups.length > 0 ? (
                        <span className="text-muted-foreground block text-xs">Through {throughGroups.join(', ')}</span>
                      ) : null}
                    </span>
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
              minLength={passwordMinLength}
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
              minLength={passwordMinLength}
              value={passwordConfirmation}
              onChange={(event) => setPasswordConfirmation(event.target.value)}
              required
            />
          </div>
          <Button type="submit" variant="outline" disabled={busy || password.length < passwordMinLength}>
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
                () => fetchWrapper.post(appPath(`/api/admin/users/${user.id}/disable`), { expected_revision: user.administration_revision }),
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
                () => fetchWrapper.post(appPath(`/api/admin/users/${user.id}/enable`), {}),
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

function GroupCard({
  group,
  users,
  clients,
  onChanged,
  onError,
}: {
  group: AccessGroup;
  users: DirectoryUser[];
  clients: OAuthClient[];
  onChanged: (message: string) => Promise<void>;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? '');
  const [candidate, setCandidate] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => setName(group.name), [group.name]);
  useEffect(() => setDescription(group.description ?? ''), [group.description]);

  const members = users.filter((user) => group.member_ids.includes(user.id));
  const candidates = users.filter((user) => !group.member_ids.includes(user.id));

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

  async function save(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.patch(appPath(`/api/admin/groups/${group.id}`), { name, description: description.trim() === '' ? null : description }),
      `Group ${name} was updated.`,
    );
  }

  async function addMember(event: FormEvent): Promise<void> {
    event.preventDefault();
    const person = users.find((user) => String(user.id) === candidate);
    if (!person) return;
    await run(
      () => fetchWrapper.put(appPath(`/api/admin/groups/${group.id}/members/${person.id}`), {}),
      `${person.name} joined ${group.name} and can sign in to its applications.`,
    );
    setCandidate('');
  }

  async function deleteGroup(): Promise<void> {
    if (!window.confirm(
      `Delete ${group.name}? Its members lose each of its applications that no direct grant or other group still gives them, and their tokens for those applications are revoked.`,
    )) return;
    await run(() => fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}`), {}), `Group ${group.name} was deleted.`);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{group.name}</CardTitle>
        <CardDescription>{group.description ?? 'Members can sign in to every application selected below.'}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => void save(event)}>
          <div className="space-y-2">
            <Label htmlFor={`group-name-${group.id}`}>Group name</Label>
            <Input id={`group-name-${group.id}`} value={name} maxLength={100} onChange={(event) => setName(event.target.value)} required />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`group-description-${group.id}`}>Description</Label>
            <Input id={`group-description-${group.id}`} value={description} maxLength={500} onChange={(event) => setDescription(event.target.value)} />
          </div>
          <Button className="self-end" type="submit" variant="outline"
            disabled={busy || name.trim() === '' || (name === group.name && description === (group.description ?? ''))}>
            Save group
          </Button>
        </form>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Applications</legend>
          <p className="text-muted-foreground text-xs">
            Every member can sign in to a selected application. Removing one revokes it from members who have no direct grant or other group for it.
          </p>
          {clients.length === 0 ? (
            <p className="text-muted-foreground text-sm">No active OAuth applications are registered.</p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {clients.map((client) => {
                const selected = group.client_ids.includes(client.id);

                return (
                  <label className="border-border flex items-center gap-3 rounded-md border p-3 text-sm" key={client.id}>
                    <input
                      type="checkbox"
                      checked={selected}
                      disabled={busy}
                      onChange={() => void run(
                        () => selected
                          ? fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}/clients/${client.id}`), {})
                          : fetchWrapper.put(appPath(`/api/admin/groups/${group.id}/clients/${client.id}`), {}),
                        `${client.name} was ${selected ? 'removed from' : 'added to'} ${group.name}.`,
                      )}
                    />
                    {client.name}
                  </label>
                );
              })}
            </div>
          )}
        </fieldset>

        <fieldset className="space-y-3">
          <legend className="text-sm font-medium">Members</legend>
          {members.length === 0 ? (
            <p className="text-muted-foreground text-sm">No members yet.</p>
          ) : (
            <ul className="divide-border divide-y rounded-md border">
              {members.map((member) => (
                <li className="flex flex-wrap items-center justify-between gap-3 p-3 text-sm" key={member.id}>
                  <span>
                    {member.name} <span className="text-muted-foreground">· {member.email}</span>
                  </span>
                  <Button type="button" variant="outline" disabled={busy} onClick={() => void run(
                    () => fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}/members/${member.id}`), {}),
                    `${member.name} left ${group.name}.`,
                  )}>
                    Remove
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => void addMember(event)}>
            <div className="space-y-2">
              <Label htmlFor={`group-candidate-${group.id}`}>Add a person</Label>
              <select
                id={`group-candidate-${group.id}`}
                className="border-input bg-background h-9 rounded-md border px-3 text-sm"
                value={candidate}
                onChange={(event) => setCandidate(event.target.value)}
              >
                <option value="">Choose a person</option>
                {candidates.map((user) => (
                  <option key={user.id} value={String(user.id)}>{user.name} ({user.email})</option>
                ))}
              </select>
            </div>
            <Button type="submit" variant="outline" disabled={busy || candidate === ''}>Add to group</Button>
          </form>
        </fieldset>

        <div className="border-destructive/40 flex flex-wrap items-center justify-between gap-3 rounded-md border p-4">
          <p className="text-muted-foreground max-w-2xl text-xs">
            Deleting the group keeps its members' accounts and direct grants.
          </p>
          <Button type="button" variant="destructive" disabled={busy} onClick={() => void deleteGroup()}>
            Delete group
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function DirectoryAdminPage() {
  const [data, setData] = useState<DirectoryResponse>({ users: [], clients: [] });
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [groupName, setGroupName] = useState('');
  const [groupDescription, setGroupDescription] = useState('');
  const [creatingGroup, setCreatingGroup] = useState(false);
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
  const [confirmationPassword, setConfirmationPassword] = useState('');
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    const [response, groupResponse] = await Promise.all([
      fetchWrapper.get(appPath('/api/admin/users')) as Promise<DirectoryResponse>,
      fetchWrapper.get(appPath('/api/admin/groups')) as Promise<GroupsResponse>,
    ]);
    setData(response);
    setGroups(groupResponse.groups);
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

  async function confirmAdministration(event: FormEvent): Promise<void> {
    event.preventDefault();
    setConfirming(true);
    setError(null);
    try {
      await fetchWrapper.post(appPath('/api/admin/confirm'), { password: confirmationPassword });
      setMessage('Provider administration confirmed for five minutes.');
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setConfirmationPassword('');
      setConfirming(false);
    }
  }

  async function createUser(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreating(true);
    setError(null);
    setMessage(null);

    try {
      await fetchWrapper.post(appPath('/api/admin/users'), {
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

  async function createGroup(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreatingGroup(true);
    setError(null);
    setMessage(null);
    try {
      await fetchWrapper.post(appPath('/api/admin/groups'), {
        name: groupName,
        description: groupDescription.trim() === '' ? null : groupDescription,
      });
      setGroupName('');
      setGroupDescription('');
      await changed('The group was created. Add applications and members to grant access.');
    } catch (caught) {
      setError(errorText(caught));
    } finally {
      setCreatingGroup(false);
    }
  }

  const reportError = (nextError: string): void => {
    setMessage(null);
    setError(nextError);
  };

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
          <CardTitle>Confirm provider administration</CardTitle>
          <CardDescription>Changing provider administrators needs a credential confirmed in the last five minutes. Sign in again with a passkey or confirm your current password here.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => void confirmAdministration(event)}>
            <div className="space-y-2">
              <Label htmlFor="administration-password">Your current password</Label>
              <Input id="administration-password" type="password" autoComplete="current-password" value={confirmationPassword}
                onChange={(event) => setConfirmationPassword(event.target.value)} required />
            </div>
            <Button type="submit" variant="outline" disabled={confirming || confirmationPassword === ''}>
              {confirming ? 'Confirming…' : 'Confirm provider administration'}
            </Button>
          </form>
        </CardContent>
      </Card>

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
                  minLength={passwordMinLength}
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
                  minLength={passwordMinLength}
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
            <Button type="submit" disabled={creating || password.length < passwordMinLength}>
              {creating ? 'Creating…' : 'Create provider account'}
            </Button>
          </form>
        </CardContent>
      </Card>

      <section className="space-y-4">
        <div>
          <h2 className="text-2xl font-semibold">Groups</h2>
          <p className="text-muted-foreground mt-1 max-w-3xl text-sm">
            A group grants its applications to every member. It decides who can sign in, never what they can do inside an application.
          </p>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Create a group</CardTitle>
          </CardHeader>
          <CardContent>
            <form className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => void createGroup(event)}>
              <div className="space-y-2">
                <Label htmlFor="new-group-name">Group name</Label>
                <Input id="new-group-name" value={groupName} maxLength={100} onChange={(event) => setGroupName(event.target.value)} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-group-description">Description</Label>
                <Input id="new-group-description" value={groupDescription} maxLength={500}
                  onChange={(event) => setGroupDescription(event.target.value)} />
              </div>
              <Button className="self-end" type="submit" disabled={creatingGroup || groupName.trim() === ''}>
                {creatingGroup ? 'Creating…' : 'Create group'}
              </Button>
            </form>
          </CardContent>
        </Card>
        {groups.map((group) => (
          <GroupCard key={group.id} group={group} users={data.users} clients={data.clients} onChanged={changed} onError={reportError} />
        ))}
      </section>

      <section className="space-y-4">
        <h2 className="text-2xl font-semibold">People</h2>
        {data.users.length === 0 ? (
          <p className="text-muted-foreground">No provider accounts exist.</p>
        ) : data.users.map((user) => (
          <UserCard
            key={user.id}
            user={user}
            clients={data.clients}
            groups={groups}
            onChanged={changed}
            onError={reportError}
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
