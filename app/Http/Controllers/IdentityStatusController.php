<?php

namespace App\Http\Controllers;

use App\Http\Middleware\AuthenticateReconciliationClient;
use App\Models\PassportClient;
use App\Models\User;
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
        // This provider currently stores subjects as positive signed bigint IDs.
        // Reject other opaque values before binding them to numeric SQL columns:
        // strict engines reject them, while permissive engines may coerce them.
        if (! preg_match('/^[1-9][0-9]{0,18}$/D', $subject)
            || (strlen($subject) === 19 && strcmp($subject, '9223372036854775807') > 0)) {
            return response()->json($inactive);
        }

        // Explicit per-client assignments are required even in the resource profile.
        // Its general OAuth consent policy deliberately also permits dynamic clients.
        $granted = DB::table('oauth_client_grants')
            ->where('subject', $subject)
            ->where('oauth_client_id', (string) $client->getKey())
            ->exists();
        $user = $granted ? User::query()->find($subject) : null;
        // Do not let a database's numeric-id coercion reinterpret an opaque subject.
        if (! $user instanceof User || ! hash_equals((string) $user->getKey(), $subject) || ! $user->canLogin()) {
            return response()->json($inactive);
        }

        return response()->json([
            'contract_version' => 1,
            'active' => true,
            'subject' => (string) $user->getKey(),
            'credential_version' => (int) $user->credential_version,
            'name' => $user->name,
            'email' => $user->email,
        ]);
    }
}
