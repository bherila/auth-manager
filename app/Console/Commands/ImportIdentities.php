<?php

namespace App\Console\Commands;

use App\Services\IdentityCopy\IdentityCopyDocument;
use App\Services\IdentityCopy\TableSequence;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Throwable;

/**
 * Create identities exported by `identity:export` on another instance, keeping their subjects.
 *
 * Relying applications bind accounts to the subject, so a copy is only useful if every subject
 * arrives unchanged. Reports what it would do and writes nothing unless --apply is passed. It
 * refuses the whole document, writing nothing, when any subject or address already belongs to
 * a different person here, or a subject was deleted here. Re-running it after a successful
 * apply changes nothing. Once the rows exist it raises the users identifier sequence to the
 * sending instance's floor, so a person created here later can never receive a subject that an
 * application already bound on the sending instance.
 */
class ImportIdentities extends Command
{
    protected $signature = 'identity:import
        {--input=php://stdin : Where to read the document. Standard input by default, so the hashes never touch disk.}
        {--apply : Write the changes. Without this the command only reports what it would do.}
        {--grant-client=* : An OAuth client id on this instance to grant every imported person who may sign in; repeatable.}
        {--next-id-at-least= : Raise the identifier sequence at least this far, above the document\'s floor.}';

    protected $description = 'Import identities exported by identity:export, preserving their subjects.';

    public function handle(): int
    {
        try {
            $document = IdentityCopyDocument::decode($this->readInput());
        } catch (InvalidArgumentException $e) {
            $this->components->error($e->getMessage().' Nothing was written.');

            return self::FAILURE;
        }

        $floor = $document->nextIdFloor;
        $minimum = $this->option('next-id-at-least');
        if ($minimum !== null) {
            if (! is_string($minimum) || preg_match('/^[1-9][0-9]{0,18}$/D', $minimum) !== 1) {
                $this->components->error('--next-id-at-least must be a positive integer.');

                return self::INVALID;
            }
            $floor = max($floor, (int) $minimum);
        }

        $sequence = new TableSequence(DB::connection());
        if (! $sequence->supported()) {
            $this->components->error('This database engine is not supported. Nothing was written.');

            return self::FAILURE;
        }

        $clients = $this->clients();
        if ($clients === null) {
            return self::FAILURE;
        }

        $plan = $this->plan($document);
        if ($plan['conflicts'] !== []) {
            foreach ($plan['conflicts'] as $conflict) {
                $this->components->error($conflict);
            }
            $this->components->error('The document conflicts with this instance. Nothing was written.');

            return self::FAILURE;
        }

        $apply = (bool) $this->option('apply');
        if (! $apply) {
            $this->components->warn('Dry run. Nothing will be written. Pass --apply to commit.');
        }

        $grants = $this->missingGrants($document, $clients);
        $nextBefore = $sequence->next('users');

        if ($apply && ($plan['create'] !== [] || $grants !== [])) {
            DB::transaction(function () use ($plan, $grants): void {
                $now = now();
                foreach ($plan['create'] as $user) {
                    DB::table('users')->insert($user + ['credential_version' => 0]);
                    AuthAuditLog::create([
                        'user_id' => $user['id'], 'acting_user_id' => null,
                        'event' => 'identity_copied_in', 'auth_method' => 'console', 'succeeded' => true,
                        'metadata' => ['command' => 'identity:import'],
                    ]);
                }
                foreach ($grants as [$clientId, $subject]) {
                    DB::table('oauth_client_grants')->insertOrIgnore([
                        'oauth_client_id' => $clientId,
                        'subject' => $subject,
                        'created_at' => $now,
                        'updated_at' => $now,
                    ]);
                }
            });
        }

        // DDL commits implicitly on MySQL and MariaDB, so the sequence moves only after the rows
        // are committed. A failure here leaves the rows in place, and a re-run only retries this.
        $nextAfter = max($nextBefore, $floor);
        $raised = false;
        if ($apply) {
            try {
                $raised = $sequence->raiseTo('users', $floor);
            } catch (Throwable) {
                $this->components->error('The identities were written, but the identifier sequence could not be raised. Re-run to retry; do not create people here until it succeeds.');

                return self::FAILURE;
            }
            $nextAfter = $sequence->next('users');
        }

        $this->newLine();
        $this->line(sprintf('users     created %d, unchanged %d', count($plan['create']), $plan['unchanged']));
        $this->line(sprintf('grants    created %d', count($grants)));
        $this->line(sprintf(
            'sequence  next id %d -> %d%s',
            $nextBefore,
            $apply ? $nextAfter : max($nextBefore, $floor),
            $apply && ! $raised ? ' (already at or above the floor)' : '',
        ));

        return self::SUCCESS;
    }

    private function readInput(): string
    {
        $path = (string) $this->option('input');
        $contents = @file_get_contents($path, false, null, 0, 16 * 1024 * 1024);

        if ($contents === false || $contents === '') {
            throw new InvalidArgumentException('No document could be read from the input.');
        }

        return $contents;
    }

    /**
     * @return list<string>|null
     */
    private function clients(): ?array
    {
        $ids = array_values(array_unique(array_map('strval', (array) $this->option('grant-client'))));
        if ($ids === []) {
            return [];
        }

        $usable = DB::table('oauth_clients')
            ->whereIn('id', $ids)
            ->where('revoked', false)
            ->pluck('id')
            ->map(static fn (mixed $id): string => (string) $id)
            ->all();

        $unknown = array_values(array_diff($ids, $usable));
        if ($unknown !== []) {
            $this->components->error('Not an active OAuth client on this instance: '.implode(', ', $unknown).'. Nothing was written.');

            return null;
        }

        return $ids;
    }

    /**
     * @return array{create: list<array<string, mixed>>, unchanged: int, conflicts: list<string>}
     */
    private function plan(IdentityCopyDocument $document): array
    {
        $create = [];
        $unchanged = 0;
        $conflicts = [];

        foreach ($document->users as $user) {
            $id = $user['id'];

            if (DB::table('identity_tombstones')->where('subject', $id)->exists()) {
                $conflicts[] = "Subject {$id} was deleted on this instance.";

                continue;
            }

            $existing = DB::table('users')->where('id', $id)->first();

            $owner = DB::table('users')
                ->whereRaw('lower(email) = ?', [strtolower(trim($user['email']))])
                ->where('id', '!=', $id)
                ->value('id');
            if ($owner !== null) {
                $conflicts[] = "Subject {$id}'s address belongs to subject {$owner} on this instance.";

                continue;
            }

            if ($existing === null) {
                $create[] = $user;

                continue;
            }

            if ($existing->deleted_at !== null) {
                $conflicts[] = "Subject {$id} was deleted on this instance.";

                continue;
            }

            $differs = array_filter(IdentityCopyDocument::COMPARED, static function (string $column) use ($existing, $user): bool {
                $here = $existing->{$column};
                $there = $user[$column];
                if (str_ends_with($column, '_at')) {
                    return IdentityCopyDocument::timestamp($here) !== $there;
                }

                return $column === 'email'
                    ? strtolower(trim((string) $here)) !== strtolower(trim((string) $there))
                    : (string) $here !== (string) $there;
            });

            if ($differs !== []) {
                $conflicts[] = "Subject {$id} already exists here with different ".implode(', ', $differs).'.';

                continue;
            }

            $unchanged++;
        }

        return ['create' => $create, 'unchanged' => $unchanged, 'conflicts' => $conflicts];
    }

    /**
     * Grants each named client to every imported person who may sign in and lacks it.
     *
     * @param  list<string>  $clients
     * @return list<array{0: string, 1: int}>
     */
    private function missingGrants(IdentityCopyDocument $document, array $clients): array
    {
        $grants = [];

        foreach ($document->users as $user) {
            if ($user['disabled_at'] !== null || ! $this->roleMaySignIn($user['user_role'])) {
                continue;
            }

            foreach ($clients as $clientId) {
                $present = DB::table('oauth_client_grants')
                    ->where('oauth_client_id', $clientId)
                    ->where('subject', $user['id'])
                    ->exists();
                if (! $present) {
                    $grants[] = [$clientId, $user['id']];
                }
            }
        }

        return $grants;
    }

    private function roleMaySignIn(string $role): bool
    {
        $roles = array_filter(array_map(
            static fn (string $value): string => strtolower(trim($value)),
            explode(',', $role),
        ));

        return in_array('user', $roles, true) || in_array('admin', $roles, true);
    }
}
