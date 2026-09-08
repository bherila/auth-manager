<?php

namespace App\Services;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Support\StaticApplicationClients;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class ApplicationRegistryService
{
    public function __construct(private readonly StaticApplicationClients $staticClients) {}

    public function save(Request $request, array $attributes, ?RegisteredApplication $application = null): RegisteredApplication
    {
        try {
            return DB::transaction(function () use ($request, $attributes, $application): RegisteredApplication {
                $clientIds = $attributes['client_ids'];
                $clients = PassportClient::query()->whereKey($clientIds)->orderBy('id')->lockForUpdate()->get();
                if ($clients->count() !== count($clientIds)
                    || $clients->contains(fn (PassportClient $client): bool => ! $this->staticClients->eligible($client))) {
                    throw ValidationException::withMessages(['client_ids' => 'Select only active static authorization-code clients registered in this provider.']);
                }

                $record = $application === null
                    ? new RegisteredApplication
                    : RegisteredApplication::query()->lockForUpdate()->findOrFail($application->id);
                if ($application === null) {
                    $record->key = $attributes['key'];
                }
                $record->fill(collect($attributes)->only(['name', 'launch_url', 'enabled'])->all());
                $record->save();
                $record->clients()->sync($clientIds);

                AuthAuditLog::create([
                    'user_id' => $request->user()->getAuthIdentifier(),
                    'acting_user_id' => $request->user()->getAuthIdentifier(),
                    'event' => $application === null ? 'application_registered' : 'application_registration_updated',
                    'auth_method' => 'admin',
                    'succeeded' => true,
                    'metadata' => ['application_key' => $record->key, 'enabled' => $record->enabled, 'oauth_client_ids' => $clientIds],
                ]);

                return $record->load('clients');
            });
        } catch (UniqueConstraintViolationException) {
            throw ValidationException::withMessages(['application' => 'The application key or OAuth client mapping is already registered.']);
        }
    }
}
