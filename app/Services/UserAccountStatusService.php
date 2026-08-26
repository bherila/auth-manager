<?php

namespace App\Services;

use App\Models\User;

class UserAccountStatusService
{
    public function credentialVersionIfActive(string $subject): ?int
    {
        $user = User::query()->find($subject);

        return $user instanceof User && $user->canLogin()
            ? (int) $user->credential_version
            : null;
    }
}
