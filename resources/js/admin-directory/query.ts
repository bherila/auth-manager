/**
 * The directory page's address state: which people the list shows and who is open. It lives
 * in the query string so a relying application can link to one person, and a reload or a
 * shared link reopens the same view.
 */
export type DirectoryStatus = '' | 'active' | 'disabled' | 'administrators';

export interface DirectoryQuery {
  search: string;
  status: DirectoryStatus;
  group: number | null;
  page: number;
  /** The open person, by the subject relying applications know them by. */
  subject: string | null;
}

export interface Pagination {
  page: number;
  per_page: number;
  total: number;
  last_page: number;
}

const STATUSES: readonly DirectoryStatus[] = ['', 'active', 'disabled', 'administrators'];

function positiveInteger(value: string | null): number | null {
  if (value === null || !/^[1-9][0-9]{0,8}$/.test(value)) {
    return null;
  }

  return Number(value);
}

/** Read the view from a query string; anything malformed falls back to the default. */
export function readQuery(search: string): DirectoryQuery {
  const params = new URLSearchParams(search);
  const status = params.get('status') ?? '';
  const subject = params.get('subject');

  return {
    search: (params.get('q') ?? '').slice(0, 255),
    status: (STATUSES as readonly string[]).includes(status) ? (status as DirectoryStatus) : '',
    group: positiveInteger(params.get('group')),
    page: positiveInteger(params.get('page')) ?? 1,
    subject: subject !== null && subject !== '' && subject.length <= 64 ? subject : null,
  };
}

/** The page's own query string for a view, leaving defaults out. */
export function pageQueryString(query: DirectoryQuery): string {
  const params = new URLSearchParams();
  if (query.search.trim() !== '') params.set('q', query.search.trim());
  if (query.status !== '') params.set('status', query.status);
  if (query.group !== null) params.set('group', String(query.group));
  if (query.page > 1) params.set('page', String(query.page));
  if (query.subject !== null) params.set('subject', query.subject);
  const text = params.toString();

  return text === '' ? '' : `?${text}`;
}

/** The list request for a view. The open person never narrows the list. */
export function listQueryString(query: DirectoryQuery, perPage: number): string {
  const params = new URLSearchParams();
  if (query.search.trim() !== '') params.set('search', query.search.trim());
  if (query.status !== '') params.set('status', query.status);
  if (query.group !== null) params.set('group', String(query.group));
  params.set('page', String(query.page));
  params.set('per_page', String(perPage));

  return `?${params.toString()}`;
}

/** "1–50 of 1,234 people", or "No people match" for an empty page. */
export function rangeLabel(pagination: Pagination, shown: number): string {
  if (pagination.total === 0 || shown === 0) {
    return 'No people match';
  }
  const first = (pagination.page - 1) * pagination.per_page + 1;
  const last = first + shown - 1;
  const total = pagination.total.toLocaleString('en-US');

  return `${first.toLocaleString('en-US')}–${last.toLocaleString('en-US')} of ${total} ${pagination.total === 1 ? 'person' : 'people'}`;
}
