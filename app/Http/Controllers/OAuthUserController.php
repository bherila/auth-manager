<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Support\RelyingApplications;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class OAuthUserController extends Controller
{
    public function __construct(private readonly RelyingApplications $applications) {}

    public function __invoke(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $subject = (string) $user->getKey();

        return response()->json([
            'sub' => $subject,
            'name' => $user->name,
            'email' => $user->email,
            // The applications this person can move between. Sent with the identity rather
            // than from an endpoint of its own so a relying application can cache it in the
            // session it is already establishing, and never has to call back here to render
            // a page. Older clients ignore the key.
            'apps' => $this->applications->forSubject($subject),
        ]);
    }
}
