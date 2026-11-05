<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

final class ConfirmProviderAdministrationController extends Controller
{
    public function __invoke(Request $request, ProviderAdministrators $administrators): JsonResponse
    {
        $input = $request->validate(['password' => ['required', 'string', 'max:4096']]);
        DB::transaction(function () use ($request, $input, $administrators): void {
            /** @var User $actor */
            $actor = $request->user();
            $locked = $administrators->actor($administrators->lockDirectory(), $actor, $request);
            if (! Hash::check($input['password'], $locked->password)) {
                throw ValidationException::withMessages(['password' => 'The password could not be confirmed.']);
            }
            // A password confirmation proves only this administrative purpose.
            // It must not refresh passkey-enrollment or OAuth authentication proof.
            $request->session()->put(ProviderAdministrators::CONFIRMATION_KEY, [
                'user_id' => (string) $locked->id,
                'credential_version' => (int) $locked->credential_version,
                'authenticated_at' => now()->timestamp,
            ]);
        }, 3);

        return response()->json(['message' => 'Provider administration confirmed for five minutes.']);
    }
}
