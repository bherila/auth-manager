<?php

namespace BWH\AuthManager\Support;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use Illuminate\Http\Request;

/** Recovery carries a client identifier, never a browser-supplied destination or OAuth state. */
final class ApplicationSignInReturn
{
    public function clientId(Request $request, bool $fromIntended = false): ?string
    {
        $id = $request->input('client_id');
        if ($id === null && $fromIntended) {
            $id = $this->intendedClient($request);
        }

        return is_string($id) && $this->application($id) !== null ? $id : null;
    }

    public function application(mixed $clientId): ?RegisteredApplication
    {
        if (! is_string($clientId) || $clientId === '' || strlen($clientId) > 100) {
            return null;
        }
        $client = PassportClient::query()->find($clientId);
        if (! $client instanceof PassportClient || ! (new StaticApplicationClients)->eligible($client)) {
            return null;
        }

        return RegisteredApplication::query()->where('enabled', true)
            ->whereHas('clients', fn ($query) => $query->whereKey($clientId))->first();
    }

    private function intendedClient(Request $request): ?string
    {
        $intended = $request->session()->get('url.intended');
        if (! is_string($intended) || strlen($intended) > 8192) {
            return null;
        }
        // Only our own authorization or continuation route can supply context. Settings,
        // invitations and arbitrary external intended URLs retain their own behavior.
        $base = strtok($intended, '?');
        if ($base !== url(Mount::path('/oauth/authorize'))
            && $base !== route('auth-manager.sign-in-return')) {
            return null;
        }
        parse_str((string) parse_url($intended, PHP_URL_QUERY), $query);
        $id = $query['client_id'] ?? null;
        if (! is_string($id) || $this->application($id) === null) {
            return null;
        }
        if ($base === url(Mount::path('/oauth/authorize'))) {
            $client = PassportClient::query()->find($id);
            if (! in_array($query['redirect_uri'] ?? null, (array) $client?->redirect_uris, true)) {
                return null;
            }
        }

        return $id;
    }
}
