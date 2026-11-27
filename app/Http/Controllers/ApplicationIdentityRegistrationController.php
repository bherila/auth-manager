<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Services\ApplicationIdentityRegistrationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

final class ApplicationIdentityRegistrationController
{
    public function __invoke(Request $request, ApplicationIdentityRegistrationService $registrations): JsonResponse
    {
        abort_if(strlen($request->getContent()) > 16384, 413);
        abort_if(array_diff(array_keys($request->all()), ['external_id', 'name', 'email', 'password_hash']) !== [], 422, 'Unexpected registration fields.');
        $data = $request->validate(['external_id' => ['required', 'uuid'], 'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'max:254'], 'password_hash' => ['required', 'string', 'max:255']]);
        $info = password_get_info($data['password_hash']);
        $options = $info['options'];
        $driver = (string) config('hashing.driver', 'bcrypt');
        $bounded = ($driver === 'bcrypt' && $info['algoName'] === 'bcrypt' && ($options['cost'] ?? 0) >= 10 && ($options['cost'] ?? 99) <= 14)
            || ($driver === 'argon2id' && $info['algoName'] === 'argon2id' && ($options['memory_cost'] ?? 0) >= 8192 && ($options['memory_cost'] ?? PHP_INT_MAX) <= 131072
                && ($options['time_cost'] ?? 0) >= 1 && ($options['time_cost'] ?? PHP_INT_MAX) <= 6
                && ($options['threads'] ?? 0) >= 1 && ($options['threads'] ?? PHP_INT_MAX) <= 4);
        if (! $bounded) {
            throw ValidationException::withMessages(['password_hash' => 'A supported, bounded password hash is required.']);
        }
        $client = $request->attributes->get(AuthenticateReconciliationClient::CLIENT_ATTRIBUTE);
        abort_unless($client instanceof PassportClient, 401);
        $result = $registrations->register($client, ['external_id' => Str::lower($data['external_id']), 'name' => trim($data['name']),
            'email' => Str::lower(trim($data['email'])), 'password_hash' => $data['password_hash']]);

        return response()->json(['contract_version' => 1, 'subject' => $result['subject'], 'initial_credential_version' => 0], $result['created'] ? 201 : 200);
    }
}
