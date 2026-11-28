import { FormEvent, useEffect, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';
import { appPath } from '@/lib/app-path';

import type { AccessGroup, OAuthClient, Outcome } from './types';
import { errorText } from './types';

interface GroupsPanelProps extends Outcome {
  groups: AccessGroup[];
  clients: OAuthClient[];
  /** Show the group's members in the People list, where membership is changed one person at a time. */
  onShowMembers: (group: AccessGroup) => void;
}

function GroupRow({ group, clients, onShowMembers, onChanged, onError }: Omit<GroupsPanelProps, 'groups'> & { group: AccessGroup }) {
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? '');
  const [busy, setBusy] = useState(false);
  const key = `group-${group.id}`;

  useEffect(() => setName(group.name), [group.name]);
  useEffect(() => setDescription(group.description ?? ''), [group.description]);

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

  return (
    <details className="border-border group rounded-md border" data-test="admin-group">
      <summary className="hover:bg-accent flex cursor-pointer items-center justify-between gap-3 px-4 py-3">
        <span className="min-w-0">
          <span className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{group.name}</span>
            {group.auto_join ? <span className="border-border shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium">Default</span> : null}
          </span>
          <span className="text-muted-foreground block truncate text-xs">
            {group.member_count} {group.member_count === 1 ? 'member' : 'members'} · {group.client_ids.length} {group.client_ids.length === 1 ? 'application' : 'applications'}
          </span>
        </span>
        <span aria-hidden="true" className="text-muted-foreground text-xs group-open:rotate-180">▾</span>
      </summary>
      <div className="border-border space-y-4 border-t p-4">
        <form className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => void save(event)}>
          <div className="space-y-1">
            <Label htmlFor={`${key}-name`}>Group name</Label>
            <Input id={`${key}-name`} value={name} maxLength={100} onChange={(event) => setName(event.target.value)} required />
          </div>
          <div className="space-y-1">
            <Label htmlFor={`${key}-description`}>Description</Label>
            <Input id={`${key}-description`} value={description} maxLength={500} onChange={(event) => setDescription(event.target.value)} />
          </div>
          <Button className="self-end" type="submit" variant="outline"
            disabled={busy || name.trim() === '' || (name === group.name && description === (group.description ?? ''))}>
            Save group
          </Button>
        </form>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Default access</legend>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-0.5" checked={group.auto_join} disabled={busy} data-test="admin-group-auto-join"
              onChange={() => {
                const next = !group.auto_join;
                if (next && !window.confirm(`Every account created from now on will join ${group.name} and can sign in to its applications at once, including accounts people create for themselves. Continue?`)) {
                  return;
                }
                void run(
                  () => fetchWrapper.put(appPath(`/api/admin/groups/${group.id}/auto-join`), { auto_join: next }),
                  next ? `New accounts now join ${group.name} automatically.` : `New accounts no longer join ${group.name}.`,
                );
              }} />
            <span>
              New accounts join this group automatically
              <span className="text-muted-foreground block text-xs">
                Existing people are not added. An operator adds them with <code>php artisan auth-manager:access-group-backfill</code>, which previews first.
                Only put applications here that every new account should reach.
              </span>
            </span>
          </label>
        </fieldset>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Applications</legend>
          <p className="text-muted-foreground text-xs">
            Every member can sign in to a selected application. Removing one revokes it from members who have no direct grant or other group for it.
          </p>
          {clients.length === 0 ? (
            <p className="text-muted-foreground text-sm">No active OAuth applications are registered.</p>
          ) : (
            <div className="grid gap-1 sm:grid-cols-2">
              {clients.map((client) => {
                const selected = group.client_ids.includes(client.id);

                return (
                  <label className="hover:bg-accent flex items-center gap-2 rounded-md p-2 text-sm" key={client.id}>
                    <input type="checkbox" checked={selected} disabled={busy}
                      onChange={() => void run(
                        () => selected
                          ? fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}/clients/${client.id}`), {})
                          : fetchWrapper.put(appPath(`/api/admin/groups/${group.id}/clients/${client.id}`), {}),
                        `${client.name} was ${selected ? 'removed from' : 'added to'} ${group.name}.`,
                      )} />
                    {client.name}
                  </label>
                );
              })}
            </div>
          )}
        </fieldset>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => onShowMembers(group)} data-test="admin-group-show-members">
            Show members in People
          </Button>
          <Button type="button" variant="destructive" size="sm" disabled={busy}
            onClick={() => {
              if (window.confirm(`Delete ${group.name}? Its members lose each of its applications that no direct grant or other group still gives them, and their tokens for those applications are revoked.`)) {
                void run(() => fetchWrapper.delete(appPath(`/api/admin/groups/${group.id}`), {}), `Group ${group.name} was deleted.`);
              }
            }}>
            Delete group
          </Button>
        </div>
        <p className="text-muted-foreground text-xs">Add or remove members from each person&apos;s Groups section. Deleting the group keeps members&apos; accounts and direct grants.</p>
      </div>
    </details>
  );
}

export function GroupsPanel({ groups, clients, onShowMembers, onChanged, onError }: GroupsPanelProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    setCreating(true);
    try {
      await fetchWrapper.post(appPath('/api/admin/groups'), { name, description: description.trim() === '' ? null : description });
      setName('');
      setDescription('');
      await onChanged('The group was created. Add applications here and members from each person.');
    } catch (caught) {
      onError(errorText(caught));
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-muted-foreground max-w-3xl text-sm">
        A group grants its applications to every member. It decides who can sign in, never what they can do inside an application.
      </p>
      <form className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]" onSubmit={(event) => void create(event)}>
        <div className="space-y-1">
          <Label htmlFor="new-group-name">Group name</Label>
          <Input id="new-group-name" value={name} maxLength={100} onChange={(event) => setName(event.target.value)} required />
        </div>
        <div className="space-y-1">
          <Label htmlFor="new-group-description">Description</Label>
          <Input id="new-group-description" value={description} maxLength={500} onChange={(event) => setDescription(event.target.value)} />
        </div>
        <Button className="self-end" type="submit" disabled={creating || name.trim() === ''}>{creating ? 'Creating…' : 'Create group'}</Button>
      </form>
      {groups.length === 0 ? (
        <p className="text-muted-foreground text-sm">No groups yet.</p>
      ) : (
        <div className="space-y-2">
          {groups.map((group) => (
            <GroupRow key={group.id} group={group} clients={clients} onShowMembers={onShowMembers} onChanged={onChanged} onError={onError} />
          ))}
        </div>
      )}
    </div>
  );
}
