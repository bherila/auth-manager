<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\TestLoginTickets;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;

final class TestLoginTicketController extends Controller
{
    public function issue(Request $request, TestLoginTickets $tickets): JsonResponse
    {
        $client = $request->attributes->get(AuthenticateReconciliationClient::CLIENT_ATTRIBUTE);
        abort_unless($client instanceof PassportClient && $tickets->clientEnabled($client), 403);
        $key = 'test-login-tickets:client:'.$client->getKey();
        abort_if(RateLimiter::tooManyAttempts($key, 30), 429);
        RateLimiter::hit($key, 60);
        abort_if(strlen($request->getContent()) > 8192, 413);
        $data = $request->validate([
            'subject' => ['required', 'string', 'max:191'], 'password' => ['required', 'string', 'max:72'],
            'authorization' => ['required', 'array', 'max:7'],
        ]);
        $ticket = $tickets->issue($client, $data['subject'], $data['password'], $data['authorization']);

        return response()->json(['contract_version' => 1, 'expires_at' => $ticket['expires_at'],
            'confirmation_uri' => route('auth-manager.test-logins.show').'#ticket='.$ticket['token']], 201)
            ->header('Cache-Control', 'private, no-store');
    }

    public function preview(Request $request, TestLoginTickets $tickets): JsonResponse
    {
        $data = $request->validate(['ticket' => ['required', 'string', 'size:43']]);
        $context = $tickets->inspect($data['ticket']);

        return response()->json(['name' => $context['user']->name, 'application' => $context['client']->name])
            ->header('Cache-Control', 'private, no-store');
    }

    public function confirm(Request $request, TestLoginTickets $tickets): JsonResponse
    {
        $data = $request->validate(['ticket' => ['required', 'string', 'size:43']]);
        $context = $tickets->inspect($data['ticket'], true);
        $user = $context['user'];
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        Auth::login($user, false);
        $request->session()->regenerate();
        AuthenticationContext::record($request, $user, ['pwd'], AuthenticationRequirement::ACR_SINGLE);
        AuthAuditLog::create(['user_id' => $user->getKey(), 'event' => 'test_login_ticket_used',
            'auth_method' => 'password', 'succeeded' => true, 'metadata' => ['oauth_client_id' => $context['client']->getKey()]]);

        return response()->json(['redirect_uri' => $context['ticket']->authorization_uri])->header('Cache-Control', 'private, no-store');
    }
}
