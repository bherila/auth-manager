import { FormEvent, ReactNode, useEffect, useRef, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';
import { appPath } from '@/lib/app-path';

import { StatusPill } from './StatusPill';
import type { AccessGroup, DirectoryUser, OAuthClient, Outcome } from './types';
import { errorText, passwordMinLength } from './types';

interface PersonDetailProps extends Outcome {
  user: DirectoryUser;
  clients: OAuthClient[];
  groups: AccessGroup[];
  passwordResetAvailable: boolean;
  onBack: () => void;
}

function Section({ id, title, description, children }: { id: string; title: string; description?: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="border-border space-y-3 border-t pt-5">
      <div>
        <h3 id={id} className="text-sm font-semibold">{title}</h3>
        {description ? <p className="text-muted-foreground mt-1 text-xs">{description}</p> : null}
      </div>
      {children}
    </section>
  );
}

/** Everything about one person, in the order an administrator usually needs it. */
export function PersonDetail({ user, clients, groups, passwordResetAvailable, onBack, onChanged, onError }: PersonDetailProps) {
  const [name, setName] = useState(user.name);
  const [email, setEmail] = useState(user.email);
  const [password, setPassword] = useState('');
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const key = `person-${user.id}`;

  useEffect(() => setName(user.name), [user.name]);
  useEffect(() => setEmail(user.email), [user.email]);
  // Opening a person moves focus to them, so a keyboard or screen-reader user lands where the content changed.
  useEffect(() => heading.current?.focus(), [user.id]);

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

  function confirmThen(question: string, action: () => Promise<unknown>, message: string): void {
    if (window.confirm(question)) {
      void run(action, message);
    }
  }

  async function updateName(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(() => fetchWrapper.patch(appPath(`/api/admin/users/${user.id}/name`), { name }), 'Provider display name was updated.');
  }

  async function updateEmail(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(() => fetchWrapper.patch(appPath(`/api/admin/users/${user.id}/email`), { email }), `${user.name}'s email address was updated.`);
  }

  async function resetPassword(event: FormEvent): Promise<void> {
    event.preventDefault();
    await run(
      () => fetchWrapper.put(appPath(`/api/admin/users/${user.id}/password`), { password, password_confirmation: passwordConfirmation }),
      `${user.name}'s password was reset and existing sessions and tokens were revoked.`,
    );
    setPassword('');
    setPasswordConfirmation('');
  }

  const isAdministrator = user.roles.includes('admin');

  return (
    <article aria-labelledby={`${key}-name`} className="space-y-5" data-test="admin-person-detail">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Button type="button" variant="link" className="mb-2 h-auto p-0 lg:hidden" onClick={onBack}>
            ← Back to people
          </Button>
          <h2 id={`${key}-name`} ref={heading} tabIndex={-1} className="truncate text-xl font-semibold outline-none">{user.name}</h2>
          <p className="text-muted-foreground truncate text-sm">{user.email}</p>
          <p className="text-muted-foreground mt-1 text-xs">
            Subject <span className="font-mono">{user.subject}</span>
            {' · '}
            {user.last_login_date ? `Last sign-in ${new Date(user.last_login_date).toLocaleString()}` : 'No recorded sign-in'}
          </p>
        </div>
        <StatusPill user={user} />
      </div>

      <Section id={`${key}-profile`} title="Profile" description="The name shown in the identity directory. Applications may use their own nickname.">
        <form className="grid gap-2 sm:grid-cols-[1fr_auto]" onSubmit={(event) => void updateName(event)}>
          <div className="space-y-1">
            <Label htmlFor={`${key}-name-input`}>Provider display name</Label>
            <Input id={`${key}-name-input`} value={name} maxLength={255} onChange={(event) => setName(event.target.value)} required />
          </div>
          <Button className="self-end" type="submit" variant="outline" disabled={busy || name.trim() === '' || name === user.name}>Save name</Button>
        </form>
        <form className="grid gap-2 sm:grid-cols-[1fr_auto]" onSubmit={(event) => void updateEmail(event)}>
          <div className="space-y-1">
            <Label htmlFor={`${key}-email-input`}>Email address</Label>
            <Input id={`${key}-email-input`} type="email" value={email} onChange={(event) => setEmail(event.target.value)} required />
          </div>
          <Button className="self-end" type="submit" variant="outline" disabled={busy || email === user.email}>Save email</Button>
        </form>
      </Section>

      <Section
        id={`${key}-recovery`}
        title="Getting back in"
        description={`${user.passkey_count === 0 ? 'No passkeys' : `${user.passkey_count} ${user.passkey_count === 1 ? 'passkey' : 'passkeys'}`}. Removing passkeys needs a credential confirmed in the last five minutes and ends this person's sessions everywhere.`}
      >
        <div className="flex flex-wrap gap-2" data-test="admin-user-sign-in-methods">
          <Button type="button" variant="outline" disabled={busy || user.passkey_count === 0} data-test="admin-user-remove-passkeys"
            onClick={() => confirmThen(
              `Remove all ${user.passkey_count} of ${user.name}'s passkeys? Their sessions in every application end, and they sign in next with their password or a recovery link.`,
              () => fetchWrapper.delete(appPath(`/api/admin/users/${user.id}/passkeys`), { expected_revision: user.administration_revision }),
              `${user.name}'s passkeys were removed and existing sessions and tokens were revoked.`,
            )}>
            Remove passkeys
          </Button>
          {passwordResetAvailable ? (
            <Button type="button" variant="outline" disabled={busy || user.status !== 'active'} data-test="admin-user-send-recovery"
              onClick={() => void run(() => fetchWrapper.post(appPath(`/api/admin/users/${user.id}/recovery`), {}), `A password reset link was emailed to ${user.email}.`)}>
              Email a password reset link
            </Button>
          ) : (
            <p className="text-muted-foreground self-center text-xs">Self-service password reset is off here, so set a temporary password below instead.</p>
          )}
        </div>
        <form className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => void resetPassword(event)}>
          <div className="space-y-1">
            <Label htmlFor={`${key}-password`}>New password</Label>
            <Input id={`${key}-password`} type="password" autoComplete="new-password" minLength={passwordMinLength} value={password}
              onChange={(event) => setPassword(event.target.value)} required />
          </div>
          <div className="space-y-1">
            <Label htmlFor={`${key}-password-confirmation`}>Confirm password</Label>
            <Input id={`${key}-password-confirmation`} type="password" autoComplete="new-password" minLength={passwordMinLength} value={passwordConfirmation}
              onChange={(event) => setPasswordConfirmation(event.target.value)} required />
          </div>
          <Button className="self-end" type="submit" variant="outline" disabled={busy || password.length < passwordMinLength}>Set password</Button>
        </form>
      </Section>

      <Section
        id={`${key}-applications`}
        title="Applications"
        description="A grant allows this person to request a token. It does not create their account or permissions in that application. A checked box is a direct grant; access through a group is shown beside it."
      >
        {clients.length === 0 ? (
          <p className="text-muted-foreground text-sm">No active OAuth applications are registered.</p>
        ) : (
          <ul className="grid gap-1 sm:grid-cols-2">
            {clients.map((client) => {
              const direct = user.direct_client_ids.includes(client.id);
              const throughGroups = groups
                .filter((group) => user.group_ids.includes(group.id) && group.client_ids.includes(client.id))
                .map((group) => group.name);
              const remaining = throughGroups.length > 0 ? ` ${user.name} keeps access through ${throughGroups.join(', ')}.` : '';

              return (
                <li key={client.id}>
                  <label className="hover:bg-accent flex items-start gap-2 rounded-md p-2 text-sm">
                    <input type="checkbox" className="mt-0.5" checked={direct} disabled={busy}
                      onChange={() => void run(
                        () => direct
                          ? fetchWrapper.delete(appPath(`/api/admin/users/${user.id}/clients/${client.id}`), {})
                          : fetchWrapper.put(appPath(`/api/admin/users/${user.id}/clients/${client.id}`), {}),
                        `${client.name} direct grant was ${direct ? `removed.${remaining}` : 'added.'} Application permissions are managed separately.`,
                      )} />
                    <span>
                      {client.name}
                      {throughGroups.length > 0 ? <span className="text-muted-foreground block text-xs">Through {throughGroups.join(', ')}</span> : null}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      <Section id={`${key}-groups`} title="Groups" description="A group grants its applications to every member.">
        {groups.length === 0 ? (
          <p className="text-muted-foreground text-sm">No groups exist.</p>
        ) : (
          <ul className="grid gap-1 sm:grid-cols-2">
            {groups.map((group) => {
              const member = user.group_ids.includes(group.id);

              return (
                <li key={group.id}>
                  <label className="hover:bg-accent flex items-center gap-2 rounded-md p-2 text-sm">
                    <input type="checkbox" checked={member} disabled={busy}
                      onChange={() => void run(
                        () => member
                          ? fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}/members/${user.id}`), {})
                          : fetchWrapper.put(appPath(`/api/admin/groups/${group.id}/members/${user.id}`), {}),
                        member ? `${user.name} left ${group.name}.` : `${user.name} joined ${group.name} and can sign in to its applications.`,
                      )} />
                    {group.name}
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      <Section id={`${key}-administrator`} title="Provider administrator" description="Controls people and credentials in this provider. OAuth grants and application administrator permissions are separate.">
        <Button type="button" variant="outline" disabled={busy || (!isAdministrator && user.status !== 'active')}
          onClick={() => confirmThen(
            `${isAdministrator ? 'Remove' : 'Grant'} provider administrator authority ${isAdministrator ? 'from' : 'for'} ${user.name}? This controls this identity directory and credentials; application permissions stay separate. Their existing sessions will end.`,
            () => fetchWrapper.put(appPath(`/api/admin/users/${user.id}/provider-administrator`), {
              administrator: !isAdministrator,
              expected_revision: user.administration_revision,
            }),
            `${user.name}'s provider administrator authority was ${isAdministrator ? 'removed' : 'granted'}.`,
          )}>
          {isAdministrator ? 'Remove provider administrator' : 'Grant provider administrator'}
        </Button>
      </Section>

      <Section id={`${key}-account`} title="Account" description="Disabling stops sign-in and revokes sessions and tokens. Deletion also removes the person; connected applications reconcile their own records.">
        <div className="flex flex-wrap gap-2">
          {user.status === 'active' ? (
            <Button type="button" variant="outline" disabled={busy}
              onClick={() => void run(
                () => fetchWrapper.post(appPath(`/api/admin/users/${user.id}/disable`), { expected_revision: user.administration_revision }),
                `${user.name} was disabled and existing sessions and tokens were revoked.`,
              )}>
              Disable person
            </Button>
          ) : (
            <Button type="button" variant="outline" disabled={busy}
              onClick={() => void run(() => fetchWrapper.post(appPath(`/api/admin/users/${user.id}/enable`), {}), `${user.name} was re-enabled.`)}>
              Re-enable person
            </Button>
          )}
          <Button type="button" variant="destructive" disabled={busy}
            onClick={() => confirmThen(
              `Delete ${user.name}? Sign-in and tokens stop immediately. Connected applications reconcile independently, and the provider record is retained temporarily. This cannot be undone from this screen.`,
              () => fetchWrapper.delete(appPath(`/api/admin/users/${user.id}`), { expected_revision: user.administration_revision }),
              `${user.name} was deleted at the provider and queued for application reconciliation.`,
            )}>
            Delete person
          </Button>
        </div>
      </Section>
    </article>
  );
}
