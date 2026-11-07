<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Show, grant or revoke a person's provider roles from the host, idempotently and audited.
 *
 * The operator path for roles nothing else grants, such as the delegated-administration roles
 * `access-view:<application>`, `access-manage:<application>`, `access-directory:<application>` and
 * `access-invite:<application>`.
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
    private const DELEGATED = '/^access-(view|manage|directory|invite):([a-z][a-z0-9-]*|\*)$/D';

    public function handle(ProviderAdministrators $administrators): int
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

        try {
            $result = DB::transaction(function () use ($user, $add, $remove, $administrators): array {
                $users = $administrators->lockDirectory();
                $locked = $administrators->target($users, $user);
                $before = $locked->roleNames();
                $after = array_values(array_diff(array_unique([...$before, ...$add]), $remove));
                $added = array_values(array_diff($after, $before));
                $removed = array_values(array_diff($before, $after));
                $administratorChanged = in_array('admin', $before, true) !== in_array('admin', $after, true);
                if (in_array('admin', $after, true) && $locked->isTestLogin()) {
                    throw ValidationException::withMessages(['user' => 'Test logins cannot hold provider-administrator authority.']);
                }
                if ($administratorChanged && in_array('admin', $before, true)) {
                    $administrators->preserveRecoveryAdministrator($users, $locked, 'demoted');
                }
                if ($administratorChanged && in_array('admin', $after, true) && $locked->disabled_at !== null) {
                    throw ValidationException::withMessages(['user' => 'Enable this account before granting provider-administrator authority.']);
                }
                if ($added !== [] || $removed !== []) {
                    $locked->user_role = implode(',', $after);
                    if ($administratorChanged) {
                        $administrators->invalidateAuthority($locked);
                    } else {
                        $locked->save();
                    }
                    AuthAuditLog::create([
                        'user_id' => $locked->id, 'acting_user_id' => null,
                        'event' => 'user_roles_changed', 'auth_method' => 'console', 'succeeded' => true,
                        'metadata' => ['added' => $added, 'removed' => $removed],
                    ]);
                }

                return [$after, $added, $removed];
            }, 3);
        } catch (ValidationException $failure) {
            foreach ($failure->errors() as $errors) {
                foreach ($errors as $error) {
                    $this->components->error($error);
                }
            }

            return self::FAILURE;
        }
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
