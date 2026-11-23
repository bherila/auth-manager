<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\ProviderSubjects;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final class IdentityStatusController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        $client = $request->attributes->get(AuthenticateReconciliationClient::CLIENT_ATTRIBUTE);
        $dynamicColumn = config('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');
        if (! $client instanceof PassportClient || ! is_string($dynamicColumn) || $dynamicColumn === ''
            || $client->getAttribute($dynamicColumn) !== null) {
            return response()->json(['message' => 'Valid relying-application credentials are required.'], 401)
                ->header('Cache-Control', 'private, no-store');
        }

        $data = $request->validate(['subject' => ['required', 'string', 'max:255']]);
        $subject = $data['subject'];
        $inactive = ['contract_version' => 1, 'active' => false];
        // Subjects are 1-64 ASCII letters and digits (ProviderSubjects). Anything else names
        // nobody, and is answered like an unknown subject without reaching the database.
        if (! ProviderSubjects::valid($subject)) {
            return response()->json($inactive);
        }

        $user = User::query()->whereProviderSubject($subject)->first();
        // Do not let a database's collation or numeric coercion stand in for the exact subject.
        if (! $user instanceof User || ! hash_equals($user->providerSubject(), $subject) || ! $user->canLogin()) {
            return response()->json($inactive);
        }
        // Explicit per-client assignments are required even in the resource profile.
        // Its general OAuth consent policy deliberately also permits dynamic clients.
        // Grants are keyed by the account's row id, not by its subject.
        $granted = DB::table('oauth_client_grants')
            ->where('subject', $user->getKey())
            ->where('oauth_client_id', (string) $client->getKey())
            ->exists();
        if (! $granted) {
            return response()->json($inactive);
        }

        // A client credential plus a caller-chosen subject proves nothing about the
        // person: grants are coarse, were backfilled to every client, and subjects are
        // sequential. Profile data (name, email) is released only through the
        // bearer-authenticated identity response, which is bound to that person's login.
        return response()->json([
            'contract_version' => 1,
            'active' => true,
            'subject' => $user->providerSubject(),
            'credential_version' => (int) $user->credential_version,
        ]);
    }
}
