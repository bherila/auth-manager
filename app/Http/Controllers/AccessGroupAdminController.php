<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\AccessGroup;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AccessGroupService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/** Provider-administrator management of access groups; see docs/access-groups.md. */
class AccessGroupAdminController extends Controller
{
    public function __construct(private readonly AccessGroupService $groups) {}

    public function index(): JsonResponse
    {
        return response()->json([
            'groups' => AccessGroup::query()->orderBy('name')->orderBy('id')->get()
                ->map(fn (AccessGroup $group): array => $this->payload($group))
                ->values(),
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $input = $this->validated($request);
        $group = $this->groups->create($request, $this->actor($request), $input['name'], $input['description']);

        return response()->json(['group' => $this->payload($group)], 201);
    }

    public function update(Request $request, AccessGroup $group): JsonResponse
    {
        $input = $this->validated($request);
        $updated = $this->groups->update($request, $this->actor($request), $group, $input['name'], $input['description']);

        return response()->json(['group' => $this->payload($updated)]);
    }

    public function destroy(Request $request, AccessGroup $group): Response
    {
        $this->groups->delete($request, $this->actor($request), $group);

        return response()->noContent();
    }

    public function addMember(Request $request, AccessGroup $group, User $user): JsonResponse
    {
        return response()->json(['group' => $this->payload($this->groups->addMember($request, $this->actor($request), $group, $user))]);
    }

    public function removeMember(Request $request, AccessGroup $group, User $user): JsonResponse
    {
        return response()->json(['group' => $this->payload($this->groups->removeMember($request, $this->actor($request), $group, $user))]);
    }

    public function addClient(Request $request, AccessGroup $group, PassportClient $client): JsonResponse
    {
        return response()->json(['group' => $this->payload($this->groups->addClient($request, $this->actor($request), $group, $client))]);
    }

    public function removeClient(Request $request, AccessGroup $group, PassportClient $client): JsonResponse
    {
        return response()->json(['group' => $this->payload($this->groups->removeClient($request, $this->actor($request), $group, $client))]);
    }

    /** @return array{name:string, description:?string} */
    private function validated(Request $request): array
    {
        $input = $request->validate([
            'name' => ['required', 'string', 'max:'.AccessGroup::NAME_MAX_LENGTH],
            'description' => ['present', 'nullable', 'string', 'max:'.AccessGroup::DESCRIPTION_MAX_LENGTH],
        ]);
        $description = $input['description'] === null ? null : trim((string) $input['description']);

        return [
            'name' => trim((string) $input['name']),
            'description' => $description === '' ? null : $description,
        ];
    }

    private function actor(Request $request): User
    {
        /** @var User $actor */
        $actor = $request->user();

        return $actor;
    }

    /**
     * @return array{id:int, name:string, description:?string, member_ids:list<int>, client_ids:list<string>}
     */
    private function payload(AccessGroup $group): array
    {
        return [
            'id' => (int) $group->getKey(),
            'name' => $group->name,
            'description' => $group->description,
            'member_ids' => array_map(static fn (string $subject): int => (int) $subject, $this->groups->memberSubjects($group, activeOnly: true)),
            'client_ids' => $this->groups->clientIds($group),
        ];
    }
}
