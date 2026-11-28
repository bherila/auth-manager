import type { DirectoryUser } from './types';

/** Status in words, never colour alone. */
export function StatusPill({ user }: { user: Pick<DirectoryUser, 'status' | 'roles'> }) {
  const active = user.status === 'active';

  return (
    <span className="flex shrink-0 gap-1">
      {user.roles.includes('admin') ? (
        <span className="border-border rounded-full border px-2 py-0.5 text-[11px] font-medium">Admin</span>
      ) : null}
      <span
        className={
          active
            ? 'rounded-full bg-success/15 px-2 py-0.5 text-[11px] font-semibold text-success'
            : 'rounded-full bg-destructive/15 px-2 py-0.5 text-[11px] font-semibold text-destructive'
        }
      >
        {active ? 'Active' : 'Disabled'}
      </span>
    </span>
  );
}
