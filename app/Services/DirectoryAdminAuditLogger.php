<?php

namespace App\Services;

use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use Illuminate\Http\Request;

class DirectoryAdminAuditLogger
{
    /**
     * @param  array<string, mixed>|null  $metadata
     */
    public function record(
        Request $request,
        User $actor,
        User $target,
        string $event,
        ?array $metadata = null,
    ): void {
        AuthAuditLog::create([
            'user_id' => $target->getKey(),
            'acting_user_id' => $actor->getKey(),
            'email' => $target->email,
            'event' => $event,
            'auth_method' => 'admin',
            'succeeded' => true,
            'ip_address' => ClientIp::resolve($request),
            'user_agent' => $request->userAgent(),
            'session_id' => $request->hasSession() ? $request->session()->getId() : null,
            'metadata' => $metadata,
        ]);
    }
}
