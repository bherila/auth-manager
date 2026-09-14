<?php

namespace App\Support;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;

/**
 * The people who can sign in to one registered application through this provider.
 *
 * The application-access page offers to provision an application account only for them (#56).
 * A person without a current grant to a static client mapped to the application cannot sign in to
 * it, so an account there would be one nobody can use; and listing anyone else would turn the
 * picker into a general directory search for whoever the application lets manage access.
 *
 * Registry mappings live on the Passport connection, so the mapped client ids are read first. They
 * are few — an application maps a handful of static clients — and they are the only values bound
 * into the people query. Grant holders are matched with a correlated subquery against the grants
 * table, never materialised into an `IN` list, so a page costs the same however many people hold a
 * grant.
 */
final class ApplicationGrantHolders
{
    public const PAGE_SIZE = 25;

    public function __construct(private readonly StaticApplicationClients $clients = new StaticApplicationClients) {}

    /**
     * Grant holders whose name or email contains the search, a page at a time.
     *
     * @return array{people: list<array{subject: string, name: string, email: string}>, next_page: int|null}
     */
    public function search(RegisteredApplication $application, string $search, int $page = 1): array
    {
        $clientIds = $this->clientIds($application);
        if ($clientIds === []) {
            return ['people' => [], 'next_page' => null];
        }

        $page = max(1, $page);
        $query = $this->holders($clientIds)->whereNull('disabled_at');

        $search = trim($search);
        if ($search !== '') {
            // `!` as the escape character, stated explicitly: SQLite gives backslash no meaning in
            // LIKE, and MySQL's reading of a backslash literal depends on the SQL mode.
            $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            $query->where(fn (Builder $inner) => $inner
                ->whereRaw("name like ? escape '!'", [$pattern])
                ->orWhereRaw("email like ? escape '!'", [$pattern]));
        }

        $users = $query->orderBy('name')->orderBy('id')
            ->offset(($page - 1) * self::PAGE_SIZE)
            ->limit(self::PAGE_SIZE + 1)
            ->get();

        $people = [];
        foreach ($users->take(self::PAGE_SIZE) as $user) {
            if ($user->canLogin()) {
                $people[] = ['subject' => (string) $user->getKey(), 'name' => (string) $user->name, 'email' => (string) $user->email];
            }
        }

        return ['people' => $people, 'next_page' => $users->count() > self::PAGE_SIZE ? $page + 1 : null];
    }

    /**
     * The grant holder a subject names, or null when it names anyone else.
     *
     * Checked again when a provisioning form is submitted: the picker lists only grant holders, and
     * a crafted form must not reach anybody else.
     */
    public function person(RegisteredApplication $application, string $subject): ?User
    {
        $clientIds = $this->clientIds($application);
        if ($clientIds === [] || ! ctype_digit($subject)) {
            return null;
        }

        $user = $this->holders($clientIds)->whereKey((int) $subject)->first();

        return $user instanceof User && $user->canLogin() ? $user : null;
    }

    /**
     * @param  list<string>  $clientIds
     * @return Builder<User>
     */
    private function holders(array $clientIds): Builder
    {
        return User::query()->whereExists(fn ($grants) => $grants
            ->selectRaw('1')
            ->from('oauth_client_grants')
            ->whereColumn('oauth_client_grants.subject', 'users.id')
            ->whereIn('oauth_client_grants.oauth_client_id', $clientIds));
    }

    /**
     * @return list<string>
     */
    private function clientIds(RegisteredApplication $application): array
    {
        return $application->clients()->get()
            ->filter(fn (PassportClient $client): bool => $this->clients->eligible($client))
            ->map(fn (PassportClient $client): string => (string) $client->id)
            ->values()
            ->all();
    }
}
