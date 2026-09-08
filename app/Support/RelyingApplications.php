<?php

namespace App\Support;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Trusted registry launch links, with a temporary static-client navigation fallback. */
class RelyingApplications
{
    /**
     * Applications the given subject may use, in display order.
     *
     * @return list<array{key: string, name: string, url: string}>
     */
    public function forSubject(string $subject): array
    {
        $staticClients = new StaticApplicationClients;
        $grantedClientIds = DB::table('oauth_client_grants')->where('subject', $subject)->pluck('oauth_client_id');
        $clients = PassportClient::query()
            ->whereIn('oauth_clients.id', $grantedClientIds)
            ->where('oauth_clients.revoked', false)
            ->orderBy('oauth_clients.name')
            ->select('oauth_clients.*')
            ->get()
            ->filter(fn (PassportClient $client): bool => $staticClients->eligible($client));

        if (config('application-registry.launch_enabled', false)) {
            return RegisteredApplication::query()
                ->where('enabled', true)
                ->whereHas('clients', fn ($query) => $query->whereIn('oauth_clients.id', $clients->modelKeys()))
                ->orderBy('name')->orderBy('key')
                ->get()
                ->map(fn (RegisteredApplication $application): array => [
                    'key' => $application->key,
                    'name' => $application->name,
                    'url' => $application->launch_url,
                ])->all();
        }

        $apps = [];

        foreach ($clients as $client) {
            $url = $this->homeUrl($client->getRawOriginal('redirect_uris'));

            if ($url === null) {
                continue;
            }

            $apps[] = [
                'key' => Str::slug((string) $client->name),
                'name' => (string) $client->name,
                'url' => $url,
            ];
        }

        return $apps;
    }

    /**
     * The origin of a client's first registered redirect URI.
     *
     * Clients with no usable absolute redirect — a personal-access or client-credentials
     * client, say — have no page to send anyone to and are simply not applications.
     */
    private function homeUrl(?string $redirectUris): ?string
    {
        $decoded = json_decode((string) $redirectUris, true);

        if (! is_array($decoded)) {
            return null;
        }

        foreach ($decoded as $uri) {
            if (! is_string($uri)) {
                continue;
            }

            $parts = parse_url($uri);

            if (! isset($parts['scheme'], $parts['host'])) {
                continue;
            }

            $port = isset($parts['port']) ? ':'.$parts['port'] : '';

            return $parts['scheme'].'://'.$parts['host'].$port;
        }

        return null;
    }
}
