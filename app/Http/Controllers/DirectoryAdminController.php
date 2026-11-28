<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\Auth\Models\PasskeyCredential;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\ProviderAdministrators;
use BWH\AuthManager\Support\ProviderSubjects;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

class DirectoryAdminController extends Controller
{
    public function __construct(private readonly DirectoryAdminService $directory) {}

    /** Rows per page when a request names none, and the most one request may ask for. */
    public const PER_PAGE = 50;

    public const MAX_PER_PAGE = 100;

    /**
     * One page of the directory, newest filter first: a name or email fragment (or an exact
     * subject), a status, a group, or one subject for a relying application's deep link. Each
     * page costs a fixed number of queries however many people the directory holds.
     */
    public function index(Request $request): JsonResponse
    {
        $input = $request->validate([
            'search' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', Rule::in(['active', 'disabled', 'administrators'])],
            'group' => ['nullable', 'integer', 'min:1'],
            'subject' => ['nullable', 'string', 'max:64'],
            'page' => ['nullable', 'integer', 'min:1', 'max:100000'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:'.self::MAX_PER_PAGE],
        ]);

        $clients = PassportClient::query()
            ->where('revoked', false)
            ->orderBy('name')
            ->get(['id', 'name'])
            ->map(static fn (PassportClient $client): array => [
                'id' => (string) $client->getKey(),
                'name' => $client->name,
            ])
            ->values();

        $query = User::query()->orderBy('name')->orderBy('id');
        $this->filter($query, $input);
        $page = $query->paginate((int) ($input['per_page'] ?? self::PER_PAGE), ['*'], 'page', (int) ($input['page'] ?? 1));
        /** @var list<User> $people */
        $people = array_values($page->items());

        return response()->json([
            'users' => $this->userPayloads($people),
            'clients' => $clients,
            'password_reset_available' => (bool) config('auth-manager.sign_in.password_reset'),
            'pagination' => [
                'page' => $page->currentPage(),
                'per_page' => $page->perPage(),
                'total' => $page->total(),
                'last_page' => $page->lastPage(),
            ],
        ]);
    }

    public function show(User $user): JsonResponse
    {
        return response()->json(['user' => $this->userPayload($user)]);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'confirmed', 'max:255', Password::min(config('auth-manager.password_min_length'))],
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

    public function updateName(Request $request, User $user): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
        ]);

        $updated = $this->directory->changeName(
            $request,
            $this->actor($request),
            $user,
            $validated['name'],
        );

        return response()->json(['user' => $this->userPayload($updated)]);
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
        $updated = $this->directory->disable($request, $this->actor($request), $user, $this->expectedRevision($request));

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function updateAdministrator(Request $request, User $user): JsonResponse
    {
        $input = $request->validate([
            'administrator' => ['required', 'boolean'],
            'expected_revision' => ['required', 'string', 'size:64', 'regex:/^[a-f0-9]+$/D'],
        ]);
        $actor = $this->actor($request);
        $updated = $this->directory->changeAdministrator($request, $actor, $user, $input['administrator'], $input['expected_revision']);
        $redirect = null;
        if ($updated->id === $actor->id && (int) $updated->credential_version !== (int) $actor->credential_version) {
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            $redirect = route('auth-manager.login');
        }

        return response()->json(['user' => $this->userPayload($updated), 'redirect' => $redirect]);
    }

    public function enable(Request $request, User $user): JsonResponse
    {
        $updated = $this->directory->enable($request, $this->actor($request), $user);

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function resetPassword(Request $request, User $user): JsonResponse
    {
        $validated = $request->validate([
            'password' => ['required', 'confirmed', 'max:255', Password::min(config('auth-manager.password_min_length'))],
        ]);

        $updated = $this->directory->resetPassword(
            $request,
            $this->actor($request),
            $user,
            $validated['password'],
        );

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function removePasskeys(Request $request, User $user): JsonResponse
    {
        $updated = $this->directory->removePasskeys($request, $this->actor($request), $user, $this->expectedRevision($request));

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function sendRecovery(Request $request, User $user): JsonResponse
    {
        $updated = $this->directory->sendRecovery($request, $this->actor($request), $user);

        return response()->json(['user' => $this->userPayload($updated)]);
    }

    public function destroy(Request $request, User $user): JsonResponse
    {
        $tombstone = $this->directory->tombstone($request, $this->actor($request), $user, $this->expectedRevision($request));

        return response()->json([
            'tombstone' => [
                'id' => $tombstone->public_id,
                'subject' => $tombstone->providerSubject(),
                'tombstoned_at' => $tombstone->tombstoned_at->toISOString(),
                'purge_after' => $tombstone->purge_after->toISOString(),
                'expected_application_count' => $tombstone->clients->count(),
            ],
        ], 202);
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

    /**
     * @param  Builder<User>  $query
     * @param  array<string, mixed>  $input
     */
    private function filter(Builder $query, array $input): void
    {
        $search = trim((string) ($input['search'] ?? ''));
        if ($search !== '') {
            $term = '%'.str_replace(['!', '%', '_'], ['!!', '!%', '!_'], mb_strtolower($search)).'%';
            $query->where(function (Builder $match) use ($search, $term): void {
                $match->whereRaw("lower(name) like ? escape '!'", [$term])
                    ->orWhereRaw("lower(email) like ? escape '!'", [$term]);
                if (ProviderSubjects::valid($search)) {
                    $match->orWhere(fn (Builder $subject) => $subject->whereProviderSubject($search));
                }
            });
        }

        $subject = $input['subject'] ?? null;
        if (is_string($subject) && $subject !== '') {
            $query->whereProviderSubject($subject);
        }

        if (isset($input['group'])) {
            $query->whereIn('id', DB::table('access_group_members')
                ->where('access_group_id', (int) $input['group'])
                ->select('subject'));
        }

        // The same rule as User::canLogin() for everyone but test logins, which the badge
        // still reports exactly.
        match ($input['status'] ?? null) {
            'active' => $query->whereNull('disabled_at')
                ->where(fn (Builder $roles) => $this->whereHasRole($roles, 'user')->orWhere(fn (Builder $admin) => $this->whereHasRole($admin, 'admin'))),
            'disabled' => $query->where(fn (Builder $inactive) => $inactive->whereNotNull('disabled_at')
                ->orWhere(fn (Builder $roles) => $roles->whereNot(fn (Builder $user) => $this->whereHasRole($user, 'user'))
                    ->whereNot(fn (Builder $admin) => $this->whereHasRole($admin, 'admin')))),
            'administrators' => $this->whereHasRole($query, 'admin'),
            default => null,
        };
    }

    /**
     * Rows whose comma-separated role list holds this role, matched as roleNames() reads it.
     *
     * @param  Builder<User>  $query
     * @return Builder<User>
     */
    private function whereHasRole(Builder $query, string $role): Builder
    {
        return $query->where(function (Builder $roles) use ($role): void {
            $column = "replace(lower(coalesce(user_role, '')), ' ', '')";
            $roles->whereRaw("{$column} = ?", [$role])
                ->orWhereRaw("{$column} like ?", [$role.',%'])
                ->orWhereRaw("{$column} like ?", ['%,'.$role])
                ->orWhereRaw("{$column} like ?", ['%,'.$role.',%']);
        });
    }

    private function actor(Request $request): User
    {
        /** @var User $actor */
        $actor = $request->user();

        return $actor;
    }

    private function expectedRevision(Request $request): ?string
    {
        return $request->validate(['expected_revision' => ['sometimes', 'required', 'string', 'size:64', 'regex:/^[a-f0-9]+$/D']])['expected_revision'] ?? null;
    }

    /**
     * @return array{
     *     id:int,
     *     subject:string,
     *     name:string,
     *     email:string,
     *     status:'active'|'disabled',
     *     roles:list<string>,
     *     administration_revision:string,
     *     disabled_at:?string,
     *     last_login_date:?string,
     *     passkey_count:int,
     *     client_ids:list<string>,
     *     direct_client_ids:list<string>,
     *     group_ids:list<int>
     * }
     */
    private function userPayload(User $user): array
    {
        return $this->userPayloads([$user])[0];
    }

    /**
     * Payloads for a page of people, from three queries in all rather than three per person.
     *
     * @param  list<User>  $users
     * @return list<array{
     *     id:int,
     *     subject:string,
     *     name:string,
     *     email:string,
     *     status:'active'|'disabled',
     *     roles:list<string>,
     *     administration_revision:string,
     *     disabled_at:?string,
     *     last_login_date:?string,
     *     passkey_count:int,
     *     client_ids:list<string>,
     *     direct_client_ids:list<string>,
     *     group_ids:list<int>
     * }>
     */
    private function userPayloads(array $users): array
    {
        if ($users === []) {
            return [];
        }

        $ids = array_map(static fn (User $user): int => (int) $user->getKey(), $users);
        $grants = DB::table('oauth_client_grants')
            ->join('oauth_clients', 'oauth_clients.id', '=', 'oauth_client_grants.oauth_client_id')
            ->whereIn('oauth_client_grants.subject', $ids)
            ->where('oauth_clients.revoked', false)
            ->orderBy('oauth_client_grants.oauth_client_id')
            ->get(['oauth_client_grants.subject', 'oauth_client_grants.oauth_client_id', 'oauth_client_grants.direct'])
            ->groupBy(static fn (object $grant): int => (int) $grant->subject);
        $groups = DB::table('access_group_members')
            ->whereIn('subject', $ids)
            ->orderBy('access_group_id')
            ->get(['subject', 'access_group_id'])
            ->groupBy(static fn (object $member): int => (int) $member->subject);
        $passkeys = PasskeyCredential::query()
            ->whereIn('user_id', $ids)
            ->groupBy('user_id')
            ->selectRaw('user_id, count(*) as aggregate')
            ->pluck('aggregate', 'user_id');
        $administrators = app(ProviderAdministrators::class);

        return array_map(static function (User $user) use ($grants, $groups, $passkeys, $administrators): array {
            $id = (int) $user->getKey();
            $own = $grants->get($id, collect());

            return [
                'id' => $id,
                'subject' => $user->providerSubject(),
                'name' => $user->name,
                'email' => $user->email,
                'status' => $user->canLogin() ? 'active' : 'disabled',
                'roles' => $user->roleNames(),
                'administration_revision' => $administrators->revision($user),
                'disabled_at' => $user->disabled_at?->toISOString(),
                'last_login_date' => $user->last_login_date?->toISOString(),
                'passkey_count' => (int) ($passkeys[$id] ?? 0),
                'client_ids' => $own->map(static fn (object $grant): string => (string) $grant->oauth_client_id)->values()->all(),
                'direct_client_ids' => $own->filter(static fn (object $grant): bool => (bool) $grant->direct)
                    ->map(static fn (object $grant): string => (string) $grant->oauth_client_id)
                    ->values()
                    ->all(),
                'group_ids' => $groups->get($id, collect())
                    ->map(static fn (object $member): int => (int) $member->access_group_id)
                    ->values()
                    ->all(),
            ];
        }, $users);
    }
}
