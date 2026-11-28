<?php

namespace BWH\AuthManager\Console\Commands;

use BWH\AuthManager\Models\AccessGroup;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Services\AccessGroupService;
use Illuminate\Console\Command;
use Illuminate\Validation\ValidationException;

/**
 * Bring existing accounts into a default-access group (docs/default-access.md).
 *
 * Without --apply it only reports how many people would join and how many would gain each of the
 * group's applications; nothing is written. Deleted accounts, test logins, current members and
 * anyone an administrator took out of the group are never added. Safe to re-run.
 */
class BackfillDefaultAccessGroup extends Command
{
    protected $signature = 'auth-manager:access-group-backfill
        {group : The group\'s id, or its exact name}
        {--apply : Add the people the preview lists}';

    protected $description = 'Preview, then add, existing accounts to a group new accounts join automatically';

    public function handle(AccessGroupService $groups): int
    {
        $identifier = (string) $this->argument('group');
        $group = ctype_digit($identifier)
            ? AccessGroup::query()->find((int) $identifier)
            : AccessGroup::query()->where('name', $identifier)->first();
        if (! $group instanceof AccessGroup) {
            $this->components->error('No such group.');

            return self::FAILURE;
        }

        $apply = (bool) $this->option('apply');
        try {
            $result = $groups->backfill($group, $apply);
        } catch (ValidationException $exception) {
            $this->components->error(collect($exception->errors())->flatten()->first() ?? 'The group cannot be backfilled.');

            return self::FAILURE;
        }

        $names = PassportClient::query()->whereIn('id', array_keys($result['applications']))->pluck('name', 'id');
        $this->components->info(sprintf('%s: %d %s %s.', $group->name, $result['people'], $result['people'] === 1 ? 'person' : 'people', $apply ? 'joined' : 'would join'));
        foreach ($result['applications'] as $clientId => $count) {
            $this->components->twoColumnDetail((string) ($names[$clientId] ?? $clientId), sprintf('%d %s', $count, $apply ? 'gained it' : 'would gain it'));
        }
        if (! $apply && $result['people'] > 0) {
            $this->line('Nothing was changed. Re-run with --apply to add them.');
        }

        return self::SUCCESS;
    }
}
