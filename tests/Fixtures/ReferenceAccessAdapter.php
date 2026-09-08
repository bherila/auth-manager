<?php

namespace Tests\Fixtures;

use App\Services\DelegatedAccess\ActorAssertionVerifier;
use App\Services\DelegatedAccess\DelegatedAccessException;
use App\Services\DelegatedAccess\DelegatedContract;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/** Synthetic consumer only. Production consumers must use their own domain authorization. */
final readonly class ReferenceAccessAdapter
{
    public function __construct(private ActorAssertionVerifier $verifier, private string $application = 'example-app') {}

    public function handle(string $assertion, string $method, string $body): array
    {
        try {
            $actorSubject = $this->verifier->verify($assertion, $method, $body);
            try {
                $input = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            } catch (Throwable) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
            if (! is_array($input) || ($input['contract_version'] ?? null) !== 1 || ($input['application'] ?? null) !== $this->application) {
                throw new DelegatedAccessException('invalid_request', 422);
            }
            unset($input['contract_version'], $input['application']);
            $payload = (new DelegatedContract)->request($this->application, $input);

            return DB::transaction(function () use ($actorSubject, $payload): array {
                // One deterministic lock order for actor, target and last-admin checks.
                $accounts = DB::table('reference_access_accounts')->orderBy('subject')->lockForUpdate()->get();
                $actor = $accounts->firstWhere('subject', $actorSubject);
                if ($actor === null || ! $actor->active || (! $actor->application_admin && json_decode($actor->managed_workspaces, true) === [])) {
                    throw new DelegatedAccessException('not_authorized', 403);
                }
                $operation = $payload['operation'];
                $envelope = ['contract_version' => 1, 'application' => $this->application, 'operation' => $operation];
                if ($operation === 'capabilities') {
                    return ['status' => 200, 'body' => [...$envelope, 'controls' => ['application_admin' => (bool) $actor->application_admin, 'workspace_permissions' => ['read', 'write']]]];
                }
                if (in_array($operation, ['subjects', 'workspaces'], true)) {
                    $items = $operation === 'subjects'
                        ? $accounts->filter(fn ($target): bool => $this->visible($actor, $target))->map(fn ($target): array => ['subject' => $target->subject, 'label' => $target->subject])->values()->all()
                        : array_map(fn (string $id): array => ['id' => $id, 'label' => $id], $actor->application_admin ? ['workspace-a', 'workspace-b'] : json_decode($actor->managed_workspaces, true));
                    $offset = 0;
                    if (isset($payload['cursor'])) {
                        try {
                            $cursor = json_decode(Crypt::decryptString($payload['cursor']), true, 16, JSON_THROW_ON_ERROR);
                            if ($cursor['application'] !== $this->application || $cursor['actor'] !== $actorSubject || $cursor['operation'] !== $operation || ! is_int($cursor['offset']) || $cursor['offset'] < 0) {
                                throw new DelegatedAccessException('invalid_cursor', 422);
                            }
                            $offset = $cursor['offset'];
                        } catch (Throwable) {
                            throw new DelegatedAccessException('invalid_cursor', 422);
                        }
                    }
                    $limit = $payload['limit'] ?? 50;
                    $next = $offset + $limit;
                    $cursor = $next < count($items) ? Crypt::encryptString(json_encode(['application' => $this->application, 'actor' => $actorSubject, 'operation' => $operation, 'offset' => $next], JSON_THROW_ON_ERROR)) : null;

                    return ['status' => 200, 'body' => [...$envelope, $operation => array_slice($items, $offset, $limit), 'next_cursor' => $cursor]];
                }
                $target = $accounts->firstWhere('subject', $payload['subject']);
                if ($target === null) {
                    if ($operation === 'update') {
                        throw new DelegatedAccessException('not_provisioned', 404);
                    }

                    return ['status' => 200, 'body' => [...$envelope, 'subject' => $payload['subject'], 'provisioned' => false, 'revision' => null, 'access' => null, 'allowed_edits' => ['application_admin' => false, 'workspaces' => false]]];
                }
                if (! $this->visible($actor, $target)) {
                    throw new DelegatedAccessException('not_authorized', 404);
                }
                if ($operation === 'update') {
                    if ($target->revision !== $payload['expected_revision']) {
                        throw new DelegatedAccessException('revision_conflict', 409);
                    }
                    $access = $payload['access'];
                    $allowed = $actor->application_admin ? ['workspace-a', 'workspace-b'] : json_decode($actor->managed_workspaces, true);
                    if ((! $actor->application_admin && $access['application_admin'] !== (bool) $target->application_admin)
                        || array_diff(array_column($access['workspaces'], 'id'), $allowed) !== []) {
                        throw new DelegatedAccessException('not_authorized', 403);
                    }
                    if ($target->application_admin && ! $access['application_admin'] && $accounts->where('active', true)->where('application_admin', true)->count() <= 1) {
                        throw new DelegatedAccessException('last_administrator', 422);
                    }
                    $target->application_admin = $access['application_admin'];
                    $target->workspaces = json_encode($access['workspaces'], JSON_THROW_ON_ERROR);
                    $target->revision = (string) Str::uuid();
                    DB::table('reference_access_accounts')->where('subject', $target->subject)->update(['application_admin' => $target->application_admin, 'workspaces' => $target->workspaces, 'revision' => $target->revision]);
                    DB::table('reference_access_audit')->insert(['actor' => $actorSubject, 'target' => $target->subject, 'application' => $this->application, 'revision' => $target->revision]);
                }

                return ['status' => 200, 'body' => [...$envelope, 'subject' => $payload['subject'], 'provisioned' => true, 'revision' => $target->revision,
                    'access' => ['application_admin' => (bool) $target->application_admin, 'workspaces' => json_decode($target->workspaces, true)],
                    'allowed_edits' => ['application_admin' => (bool) $actor->application_admin, 'workspaces' => true]]];
            });
        } catch (DelegatedAccessException $exception) {
            return ['status' => $exception->status, 'body' => ['error' => $exception->outcome]];
        }
    }

    private function visible(object $actor, object $target): bool
    {
        return $actor->application_admin || (! $target->application_admin
            && array_diff(array_column(json_decode($target->workspaces, true), 'id'), json_decode($actor->managed_workspaces, true)) === []);
    }
}
