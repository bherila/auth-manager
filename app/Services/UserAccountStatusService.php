<?php

namespace App\Services;

use App\Models\User;

class UserAccountStatusService
{
    public function allowsSignIn(string $subject): bool
    {
        $user = User::query()->find($subject);

        return $user instanceof User && $user->canLogin();
    }
}
