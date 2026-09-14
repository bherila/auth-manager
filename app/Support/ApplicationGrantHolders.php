<?php

namespace App\Support;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * The people who can sign in to one registered application through this provider.
 *
 * The application-access page offers to provision an application account only for them (#56).
 * A person without a current grant to a static client mapped to the application cannot sign in to
 * it, so an account there would be one nobody can use; and listing anyone else would turn the
 * picker into a general directory search for whoever the application lets manage access.
 *
 * Grants live on the provider connection and registry mappings on the Passport connection, so the
 * mapped client ids are read first and the grants queried separately, never joined.
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
        $subjects = $this->subjects($application);
        if ($subjects === []) {
            return ['people' => [], 'next_page' => null];
        }

        $page = max(1, $page);
        $query = User::query()->whereIn('id', $subjects)->whereNull('disabled_at');

        $search = trim($search);
        if ($search !== '') {
            $pattern = '%'.addcslashes($search, '\\%_').'%';
            $query->where(fn ($inner) => $inner->where('name', 'like', $pattern)->orWhere('email', 'like', $pattern));
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
        if (! ctype_digit($subject) || ! in_array($subject, $this->subjects($application), true)) {
            return null;
        }

        $user = User::query()->find((int) $subject);

        return $user instanceof User && $user->canLogin() ? $user : null;
    }

    /**
     * @return list<string>
     */
    private function subjects(RegisteredApplication $application): array
    {
        $clientIds = $application->clients()->get()
            ->filter(fn (PassportClient $client): bool => $this->clients->eligible($client))
            ->map(fn (PassportClient $client): string => (string) $client->id)
            ->values()
            ->all();

        if ($clientIds === []) {
            return [];
        }

        return DB::table('oauth_client_grants')
            ->whereIn('oauth_client_id', $clientIds)
            ->distinct()
            ->pluck('subject')
            ->map(fn (mixed $subject): string => (string) $subject)
            ->values()
            ->all();
    }
}
