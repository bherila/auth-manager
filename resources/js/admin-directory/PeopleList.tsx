import { useId } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

import type { DirectoryQuery, DirectoryStatus, Pagination } from './query';
import { rangeLabel } from './query';
import { StatusPill } from './StatusPill';
import type { AccessGroup, DirectoryUser } from './types';

interface PeopleListProps {
  query: DirectoryQuery;
  searchText: string;
  onSearchText: (value: string) => void;
  onQuery: (next: Partial<DirectoryQuery>) => void;
  people: DirectoryUser[];
  pagination: Pagination;
  loading: boolean;
  groups: AccessGroup[];
  selectedSubject: string | null;
  onSelect: (user: DirectoryUser) => void;
}

const STATUS_LABELS: Record<DirectoryStatus, string> = {
  '': 'Everyone',
  active: 'Active',
  disabled: 'Disabled',
  administrators: 'Provider administrators',
};

/** The master list: search, filter and one compact row per person, a page at a time. */
export function PeopleList({
  query, searchText, onSearchText, onQuery, people, pagination, loading, groups, selectedSubject, onSelect,
}: PeopleListProps) {
  const id = useId();
  const selectClass = 'border-input bg-background h-9 w-full rounded-md border px-2 text-sm';

  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <Label htmlFor={`${id}-search`}>Search people</Label>
        <Input id={`${id}-search`} type="search" value={searchText} maxLength={255} placeholder="Name, email or subject"
          autoComplete="off" onChange={(event) => onSearchText(event.target.value)} data-test="admin-directory-search" />
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label htmlFor={`${id}-status`}>Status</Label>
          <select id={`${id}-status`} className={selectClass} value={query.status}
            onChange={(event) => onQuery({ status: event.target.value as DirectoryStatus, page: 1 })}>
            {(Object.keys(STATUS_LABELS) as DirectoryStatus[]).map((status) => (
              <option key={status} value={status}>{STATUS_LABELS[status]}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor={`${id}-group`}>Group</Label>
          <select id={`${id}-group`} className={selectClass} value={query.group === null ? '' : String(query.group)}
            onChange={(event) => onQuery({ group: event.target.value === '' ? null : Number(event.target.value), page: 1 })}>
            <option value="">Any group</option>
            {groups.map((group) => <option key={group.id} value={String(group.id)}>{group.name}</option>)}
          </select>
        </div>
      </div>

      <p className="text-muted-foreground text-xs" role="status" aria-live="polite" data-test="admin-directory-count">
        {loading ? 'Loading people…' : rangeLabel(pagination, people.length)}
      </p>

      <ul className="divide-border border-border max-h-[70vh] divide-y overflow-y-auto rounded-md border" aria-busy={loading}
        aria-label="People" data-test="admin-directory-people">
        {loading && people.length === 0
          ? Array.from({ length: 6 }, (_, index) => (
            <li key={index} aria-hidden="true" className="space-y-1 p-3">
              <div className="bg-muted h-4 w-2/3 animate-pulse rounded" />
              <div className="bg-muted h-3 w-1/2 animate-pulse rounded" />
            </li>
          ))
          : people.map((person) => {
            const selected = person.subject === selectedSubject;

            return (
              <li key={person.id}>
                <button type="button" onClick={() => onSelect(person)} aria-current={selected ? 'true' : undefined}
                  className={`hover:bg-accent focus-visible:ring-ring/50 flex w-full items-center gap-3 px-3 py-2 text-left outline-none focus-visible:ring-[3px] ${selected ? 'bg-accent' : ''}`}
                  data-test="admin-directory-person">
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{person.name}</span>
                    <span className="text-muted-foreground block truncate text-xs">{person.email}</span>
                  </span>
                  <StatusPill user={person} />
                </button>
              </li>
            );
          })}
      </ul>

      <nav aria-label="People pages" className="flex items-center justify-between gap-2">
        <Button type="button" variant="outline" size="sm" disabled={loading || pagination.page <= 1}
          onClick={() => onQuery({ page: pagination.page - 1 })}>
          Previous
        </Button>
        <span className="text-muted-foreground text-xs">Page {pagination.page} of {Math.max(pagination.last_page, 1)}</span>
        <Button type="button" variant="outline" size="sm" disabled={loading || pagination.page >= pagination.last_page}
          onClick={() => onQuery({ page: pagination.page + 1 })}>
          Next
        </Button>
      </nav>
    </div>
  );
}
