<?php

namespace App\Console\Commands;

use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * Show, grant or revoke a person's provider roles from the host, idempotently and audited.
 *
 * The operator path for roles nothing else grants, such as the delegated-administration roles
 * `access-view:<application>`, `access-manage:<application>` and `access-directory:<application>`.
 * Without --add or --remove it only shows the current roles.
 */
class ManageUserRoles extends Command
{
    protected $signature = 'auth-manager:user-roles
        {user : The person\'s id, or their exact email address}
        {--add=* : A role to grant; repeatable}
        {--remove=* : A role to revoke; repeatable}';

    protected $description = 'Show, grant or revoke a person\'s provider roles';

    /** Lowercase, no separators: a role is one token of the comma-separated user_role list. */
    private const ROLE = '/^[a-z][a-z0-9_-]*(:([a-z][a-z0-9-]*|\*))?$/D';

    /** The delegated-administration roles name one permission and one application, or every application. */
    private const DELEGATED = '/^access-(view|manage|directory):([a-z][a-z0-9-]*|\*)$/D';

    public function handle(): int
    {
        $add = array_values(array_unique(array_map(static fn (string $role): string => strtolower(trim($role)), (array) $this->option('add'))));
        $remove = array_values(array_unique(array_map(static fn (string $role): string => strtolower(trim($role)), (array) $this->option('remove'))));
        foreach ([...$add, ...$remove] as $role) {
            if (preg_match(self::ROLE, $role) !== 1 || (str_starts_with($role, 'access-') && preg_match(self::DELEGATED, $role) !== 1)) {
                $this->components->error("Not a role: {$role}");

                return self::INVALID;
            }
        }
        if (array_intersect($add, $remove) !== []) {
            $this->components->error('A role cannot be both added and removed.');

            return self::INVALID;
        }

        $identifier = (string) $this->argument('user');
        $user = ctype_digit($identifier)
            ? User::query()->find((int) $identifier)
            : User::query()->whereRaw('lower(email) = ?', [strtolower($identifier)])->first();
        if (! $user instanceof User) {
            $this->components->error('No such person.');

            return self::FAILURE;
        }

        $result = DB::transaction(function () use ($user, $add, $remove): array {
            $locked = User::query()->lockForUpdate()->findOrFail($user->id);
            $before = $locked->roleNames();
            $after = array_values(array_diff(array_unique([...$before, ...$add]), $remove));
            $added = array_values(array_diff($after, $before));
            $removed = array_values(array_diff($before, $after));
            if ($added !== [] || $removed !== []) {
                $locked->forceFill(['user_role' => implode(',', $after)])->save();
                AuthAuditLog::create([
                    'user_id' => $locked->id, 'acting_user_id' => null,
                    'event' => 'user_roles_changed', 'auth_method' => 'console', 'succeeded' => true,
                    'metadata' => ['added' => $added, 'removed' => $removed],
                ]);
            }

            return [$after, $added, $removed];
        });
        [$roles, $added, $removed] = $result;

        if ($added === [] && $removed === []) {
            $this->components->info(($add === [] && $remove === [] ? 'Roles' : 'Unchanged').": {$this->describe($roles)}");
        } else {
            $this->components->info(sprintf('Added %s; removed %s. Roles: %s', $this->describe($added), $this->describe($removed), $this->describe($roles)));
        }

        return self::SUCCESS;
    }

    /**
     * @param  list<string>  $roles
     */
    private function describe(array $roles): string
    {
        return $roles === [] ? 'none' : implode(', ', $roles);
    }
}
