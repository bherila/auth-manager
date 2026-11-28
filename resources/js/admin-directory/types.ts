import type { Pagination } from './query';

export interface OAuthClient {
  id: string;
  name: string;
}

export interface DirectoryUser {
  id: number;
  subject: string;
  name: string;
  email: string;
  status: 'active' | 'disabled';
  roles: string[];
  administration_revision: string;
  disabled_at: string | null;
  last_login_date: string | null;
  passkey_count: number;
  client_ids: string[];
  direct_client_ids: string[];
  group_ids: number[];
  /** Default groups an administrator took this person out of; a backfill never re-adds them. */
  opted_out_group_ids: number[];
}

export interface DirectoryResponse {
  users: DirectoryUser[];
  clients: OAuthClient[];
  password_reset_available: boolean;
  pagination: Pagination;
}

export interface AccessGroup {
  id: number;
  name: string;
  description: string | null;
  /** New accounts join this group automatically: the instance's default access. */
  auto_join: boolean;
  member_count: number;
  client_ids: string[];
}

export interface GroupsResponse {
  groups: AccessGroup[];
}

/** Every directory request reports its outcome through these two callbacks. */
export interface Outcome {
  onChanged: (message: string) => Promise<void>;
  onError: (message: string) => void;
}

export function errorText(error: unknown): string {
  return typeof error === 'string' ? error : error instanceof Error ? error.message : 'The request failed.';
}

export const passwordMinLength = Number(document.getElementById('directory-admin-mount')?.dataset.passwordMinLength);
