<?php

namespace App\Http\Controllers;

use App\Models\PassportClient;
use App\Models\User;
use App\Services\DirectoryAdminService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class DirectoryAdminController extends Controller
{
    public function __construct(private readonly DirectoryAdminService $directory) {}

    public function index(): JsonResponse
    {
        $clients = PassportClient::query()
            ->where('revoked', false)
            ->orderBy('name')
            ->get(['id', 'name'])
            ->map(static fn (PassportClient $client): array => [
                'id' => (string) $client->getKey(),
                'name' => $client->name,
            ])
            ->values();

        $users = User::query()
            ->orderBy('name')
            ->orderBy('id')
            ->get()
            ->map(fn (User $user): array => $this->userPayload($user))
            ->values();

        return response()->json([
            'users' => $users,
            'clients' => $clients,
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'confirmed', 'max:255', Password::min(12)],
            'enabled' => ['required', 'boolean'],
            'client_ids' => ['present', 'array', 'max:100'],
            'client_ids.*' => ['string', 'uuid', 'distinct'],
        ]);

        $user = $this->directory->create($request, $this->actor($request), [
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => $validated['password'],
            'enabled' => $validated['enabled'],
            'client_ids' => $validated['client_ids'],
        ]);

        return response()->json(['user' => $this->userPayload($user)], 201);
    }

    public function updateEmail(Request $request, User $user): JsonResponse
    {
        $validated = $request->validate([
            'email' => [
                'required',
                'email',
                'max:255',
                Rule::unique('users', 'email')->ignore($user->getKey()),
            ],
        ]);

        $updated = $this->directory->changeEmail(
            $request,
            $this->actor($request),
            $user,
            $validated['email'],
        );

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function disable(Request $request, User $user): JsonResponse
    {
        $updated = $this->directory->disable($request, $this->actor($request), $user);

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function enable(Request $request, User $user): JsonResponse
    {
        $updated = $this->directory->enable($request, $this->actor($request), $user);

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function resetPassword(Request $request, User $user): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'confirmed', 'max:255', Password::min(12)],
        ]);

        $updated = $this->directory->resetPassword(
            $request,
            $this->actor($request),
            $user,
            $validated['password'],
        );

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function grantClient(Request $request, User $user, PassportClient $client): JsonResponse
    {
        $updated = $this->directory->grantClient(
            $request,
            $this->actor($request),
            $user,
            $client,
        );

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function revokeClient(Request $request, User $user, PassportClient $client): JsonResponse
    {
        $updated = $this->directory->revokeClient(
            $request,
            $this->actor($request),
            $user,
            $client,
        );

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    private function actor(Request $request): User
    {
        /** @var User $actor */
        $actor = $request->user();

        return $actor;
    }

    /**
     * @return array{
     *     id:int,
     *     name:string,
     *     email:string,
     *     status:'active'|'disabled',
     *     roles:list<string>,
     *     disabled_at:?string,
     *     last_login_date:?string,
     *     client_ids:list<string>
     * }
     */
    private function userPayload(User $user): array
    {
        $clientIds = DB::table('oauth_client_grants')
            ->join('oauth_clients', 'oauth_clients.id', '=', 'oauth_client_grants.oauth_client_id')
            ->where('subject', $user->getKey())
            ->where('oauth_clients.revoked', false)
            ->orderBy('oauth_client_id')
            ->pluck('oauth_client_grants.oauth_client_id')
            ->map(static fn (mixed $id): string => (string) $id)
            ->all();

        return [
            'id' => (int) $user->getKey(),
            'name' => $user->name,
            'email' => $user->email,
            'status' => $user->canLogin() ? 'active' : 'disabled',
            'roles' => $user->roleNames(),
            'disabled_at' => $user->disabled_at?->toISOString(),
            'last_login_date' => $user->last_login_date?->toISOString(),
            'client_ids' => $clientIds,
        ];
    }
}
