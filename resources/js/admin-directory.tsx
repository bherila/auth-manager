import { FormEvent, KeyboardEvent, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { GroupsPanel } from '@/admin-directory/GroupsPanel';
import { NewPersonForm } from '@/admin-directory/NewPersonForm';
import { PeopleList } from '@/admin-directory/PeopleList';
import { PersonDetail } from '@/admin-directory/PersonDetail';
import type { DirectoryQuery } from '@/admin-directory/query';
import { listQueryString, pageQueryString, readQuery } from '@/admin-directory/query';
import type { AccessGroup, DirectoryResponse, DirectoryUser, GroupsResponse } from '@/admin-directory/types';
import { errorText } from '@/admin-directory/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { fetchWrapper } from '@/fetchWrapper';
import { appPath } from '@/lib/app-path';

const PER_PAGE = 50;
const SEARCH_DELAY_MS = 300;

type Tab = 'people' | 'groups' | 'new';

const TABS: { id: Tab; label: string }[] = [
  { id: 'people', label: 'People' },
  { id: 'groups', label: 'Groups' },
  { id: 'new', label: 'Add a person' },
];

const EMPTY: DirectoryResponse = {
  users: [],
  clients: [],
  password_reset_available: false,
  pagination: { page: 1, per_page: PER_PAGE, total: 0, last_page: 1 },
};

function ConfirmAdministration({ onMessage, onError }: { onMessage: (message: string) => void; onError: (message: string) => void }) {
  const [password, setPassword] = useState('');
  const [confirming, setConfirming] = useState(false);

  async function confirm(event: FormEvent): Promise<void> {
    event.preventDefault();
    setConfirming(true);
    try {
      await fetchWrapper.post(appPath('/api/admin/confirm'), { password });
      onMessage('Provider administration confirmed for five minutes.');
    } catch (caught) {
      onError(errorText(caught));
    } finally {
      setPassword('');
      setConfirming(false);
    }
  }

  return (
    <details className="border-border rounded-md border text-sm">
      <summary className="hover:bg-accent cursor-pointer px-4 py-2 font-medium">Confirm provider administration</summary>
      <div className="border-border space-y-2 border-t p-4">
        <p className="text-muted-foreground text-xs">
          Changing provider administrators or removing someone&apos;s passkeys needs a credential confirmed in the last five minutes.
          Sign in again with a passkey, or confirm your current password here.
        </p>
        <form className="flex flex-wrap items-end gap-2" onSubmit={(event) => void confirm(event)}>
          <div className="space-y-1">
            <Label htmlFor="administration-password">Your current password</Label>
            <Input id="administration-password" type="password" autoComplete="current-password" value={password}
              onChange={(event) => setPassword(event.target.value)} required />
          </div>
          <Button type="submit" variant="outline" disabled={confirming || password === ''}>
            {confirming ? 'Confirming…' : 'Confirm'}
          </Button>
        </form>
      </div>
    </details>
  );
}

function DirectoryAdminPage() {
  const [tab, setTab] = useState<Tab>('people');
  const [query, setQuery] = useState<DirectoryQuery>(() => readQuery(window.location.search));
  const [searchText, setSearchText] = useState(query.search);
  const [data, setData] = useState<DirectoryResponse>(EMPTY);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [selected, setSelected] = useState<DirectoryUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const tabRefs = useRef<Record<Tab, HTMLButtonElement | null>>({ people: null, groups: null, new: null });

  const updateQuery = useCallback((next: Partial<DirectoryQuery>): void => {
    setQuery((current) => ({ ...current, ...next }));
  }, []);

  // The address follows the view, so a reload or a shared link reopens it.
  useEffect(() => {
    window.history.replaceState(null, '', `${window.location.pathname}${pageQueryString(query)}`);
  }, [query]);

  useEffect(() => {
    if (searchText.trim() === query.search.trim()) return undefined;
    const timer = window.setTimeout(() => updateQuery({ search: searchText, page: 1 }), SEARCH_DELAY_MS);

    return () => window.clearTimeout(timer);
  }, [searchText, query.search, updateQuery]);

  const listRequest = listQueryString(query, PER_PAGE);
  // A refresh after a change runs from an older render, so the loader reads the view that is
  // on screen now, and only the newest request for that view may update the page.
  const currentListRequest = useRef(listRequest);
  currentListRequest.current = listRequest;
  const listGeneration = useRef(0);
  const loadList = useCallback(async (): Promise<void> => {
    const request = currentListRequest.current;
    const generation = ++listGeneration.current;
    const current = (): boolean => generation === listGeneration.current && request === currentListRequest.current;
    setLoading(true);
    try {
      const response = await fetchWrapper.get(appPath(`/api/admin/users${request}`)) as DirectoryResponse;
      if (current()) {
        setData(response);
      }
    } finally {
      if (generation === listGeneration.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void loadList().catch((caught) => setError(errorText(caught)));
  }, [listRequest, loadList]);

  const loadGroups = useCallback(async (): Promise<void> => {
    setGroups(((await fetchWrapper.get(appPath('/api/admin/groups'))) as GroupsResponse).groups);
  }, []);

  const selectedRef = useRef<DirectoryUser | null>(null);
  selectedRef.current = selected;
  // Bumped whenever the open person changes, so a read started for someone else is dropped.
  const selectionGeneration = useRef(0);

  /** Opening a person by address: a row click already holds them; a link or reload asks by subject. */
  const loadSelected = useCallback(async (subject: string | null): Promise<void> => {
    if (subject === null) {
      setSelected(null);
      return;
    }
    if (selectedRef.current?.subject === subject) {
      return;
    }
    const generation = ++selectionGeneration.current;
    const params = new URLSearchParams({ subject, per_page: '1' });
    const response = await fetchWrapper.get(appPath(`/api/admin/users?${params.toString()}`)) as DirectoryResponse;
    if (generation !== selectionGeneration.current) {
      return;
    }
    setSelected(response.users[0] ?? null);
    if (response.users.length === 0) {
      setError('No provider account has that subject.');
    }
  }, []);


  useEffect(() => {
    void loadGroups().catch((caught) => setError(errorText(caught)));
  }, [loadGroups]);

  useEffect(() => {
    void loadSelected(query.subject).catch((caught) => setError(errorText(caught)));
  }, [query.subject, loadSelected]);

  function open(person: DirectoryUser | null): void {
    selectionGeneration.current++;
    selectedRef.current = person;
    setSelected(person);
    updateQuery({ subject: person?.subject ?? null });
  }

  async function changed(nextMessage: string): Promise<void> {
    setError(null);
    setMessage(nextMessage);
    try {
      await Promise.all([loadList(), loadGroups()]);
      const current = selectedRef.current;
      if (current !== null) {
        const generation = selectionGeneration.current;
        try {
          const refreshed = ((await fetchWrapper.get(appPath(`/api/admin/users/${current.id}`))) as { user: DirectoryUser }).user;
          if (generation === selectionGeneration.current) {
            setSelected(refreshed);
          }
        } catch {
          // Deleted: there is nobody left to show, unless another person was opened meanwhile.
          if (generation === selectionGeneration.current) {
            open(null);
          }
        }
      }
    } catch (caught) {
      setError(errorText(caught));
    }
  }

  function reportError(nextError: string): void {
    setMessage(null);
    setError(nextError);
  }

  function onTabKey(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    const step = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
    if (step === 0) return;
    event.preventDefault();
    const next = TABS[(index + step + TABS.length) % TABS.length].id;
    setTab(next);
    tabRefs.current[next]?.focus();
  }

  return (
    <main className="mx-auto max-w-7xl space-y-6 px-4 py-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-primary text-sm font-semibold">Identity provider</p>
          <h1 className="text-2xl font-bold tracking-tight">Directory administration</h1>
          <p className="text-muted-foreground mt-1 max-w-3xl text-sm">
            Manage provider sign-in, credentials, and coarse application grants here. Each connected application owns its own accounts and permissions.
          </p>
        </div>
        <ConfirmAdministration onMessage={(next) => { setError(null); setMessage(next); }} onError={reportError} />
      </header>

      <div aria-live="polite">
        {error ? <p className="border-destructive bg-destructive/10 text-destructive rounded-md border p-3 text-sm" role="alert">{error}</p> : null}
        {message ? <p className="border-success bg-success/10 text-success rounded-md border p-3 text-sm">{message}</p> : null}
      </div>

      <div role="tablist" aria-label="Directory" className="border-border flex gap-1 border-b">
        {TABS.map((item, index) => (
          <button key={item.id} ref={(element) => { tabRefs.current[item.id] = element; }} type="button" role="tab"
            id={`tab-${item.id}`} aria-controls={`panel-${item.id}`} aria-selected={tab === item.id} tabIndex={tab === item.id ? 0 : -1}
            onClick={() => setTab(item.id)} onKeyDown={(event) => onTabKey(event, index)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 ${tab === item.id ? 'border-primary' : 'text-muted-foreground border-transparent hover:text-foreground'}`}>
            {item.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id="panel-people" aria-labelledby="tab-people" hidden={tab !== 'people'}>
        <div className="grid gap-6 lg:grid-cols-[22rem_minmax(0,1fr)]">
          <div className={selected !== null ? 'hidden lg:block' : ''}>
            <PeopleList query={query} searchText={searchText} onSearchText={setSearchText} onQuery={updateQuery}
              people={data.users} pagination={data.pagination} loading={loading} groups={groups}
              selectedSubject={selected?.subject ?? null} onSelect={open} />
          </div>
          <div className={selected === null ? 'hidden lg:block' : ''}>
            {selected !== null ? (
              <PersonDetail key={selected.id} user={selected} clients={data.clients} groups={groups}
                passwordResetAvailable={data.password_reset_available} onBack={() => open(null)}
                onChanged={changed} onError={reportError} />
            ) : (
              <p className="text-muted-foreground border-border rounded-md border border-dashed p-8 text-center text-sm">
                Choose a person to see their sign-in, applications and groups.
              </p>
            )}
          </div>
        </div>
      </div>

      <div role="tabpanel" id="panel-groups" aria-labelledby="tab-groups" hidden={tab !== 'groups'}>
        <GroupsPanel groups={groups} clients={data.clients} onChanged={changed} onError={reportError}
          onShowMembers={(group) => {
            // Close any open person, or a narrow screen keeps showing them instead of the members.
            selectionGeneration.current++;
            selectedRef.current = null;
            setSelected(null);
            setSearchText('');
            updateQuery({ group: group.id, search: '', status: '', page: 1, subject: null });
            setTab('people');
          }} />
      </div>

      <div role="tabpanel" id="panel-new" aria-labelledby="tab-new" hidden={tab !== 'new'}>
        <NewPersonForm clients={data.clients} onError={reportError}
          onCreated={async (person, nextMessage) => {
            open(person);
            await changed(nextMessage);
            setTab('people');
          }} />
      </div>
    </main>
  );
}

const mount = document.getElementById('directory-admin-mount');
if (mount) {
  createRoot(mount).render(<DirectoryAdminPage />);
}
