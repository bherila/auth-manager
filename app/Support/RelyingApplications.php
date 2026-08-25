<?php

namespace App\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The applications a person can move between, as this service knows them.
 *
 * There is no separate registry to maintain: an application exists here because it has an
 * OAuth client, and its home page is the origin of the redirect URI that client already
 * registered. That URI is authoritative — it is what the token endpoint validates against —
 * so deriving from it cannot drift from reality the way a hand-kept list would.
 */
class RelyingApplications
{
    /**
     * Applications the given subject may use, in display order.
     *
     * The subject argument is the seam for per-client entitlement: today everyone who can
     * sign in can reach everything, so the filter is a no-op, but the shape is already the
     * one entitlement will need and callers will not have to change when it lands.
     *
     * @return list<array{key: string, name: string, url: string}>
     */
    public function forSubject(string $subject): array
    {
        $apps = [];

        foreach (DB::table('oauth_clients')->where('revoked', false)->orderBy('name')->get() as $client) {
            $url = $this->homeUrl($client->redirect_uris ?? null);

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
