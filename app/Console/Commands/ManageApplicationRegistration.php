<?php

namespace App\Console\Commands;

use App\Http\Requests\SaveRegisteredApplicationRequest;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Services\ApplicationRegistryService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

/**
 * Show, register or update an application registry entry from the host.
 *
 * The same rules, client eligibility checks and audit as the admin registry page, for an
 * instance whose registry is empty or whose operator works from the host. Clients are named
 * by id or exact name. Without --name, --launch-url, --client, --enable or --disable it only
 * shows the entry.
 */
class ManageApplicationRegistration extends Command
{
    protected $signature = 'auth-manager:application
        {key : The registry key, for example example-app}
        {--name= : Display name (required when registering)}
        {--launch-url= : Absolute HTTPS launch URL (required when registering)}
        {--client=* : An OAuth client id or exact name to attach; repeatable, replaces the attached set}
        {--enable : Enable the entry}
        {--disable : Disable the entry}';

    protected $description = 'Show, register or update an application registry entry';

    public function handle(ApplicationRegistryService $registry): int
    {
        $key = (string) $this->argument('key');
        $existing = RegisteredApplication::query()->with('clients')->where('key', $key)->first();
        $changing = $this->option('name') !== null || $this->option('launch-url') !== null
            || $this->option('client') !== [] || $this->option('enable') || $this->option('disable');

        if (! $changing) {
            if ($existing === null) {
                $this->components->error("No application is registered as {$key}.");

                return self::FAILURE;
            }
            $this->show($existing);

            return self::SUCCESS;
        }
        if ($this->option('enable') && $this->option('disable')) {
            $this->components->error('Choose --enable or --disable, not both.');

            return self::INVALID;
        }

        $clientIds = $existing?->clients->modelKeys() ?? [];
        if ($this->option('client') !== []) {
            $clientIds = [];
            foreach ((array) $this->option('client') as $reference) {
                $matches = PassportClient::query()->whereKey($reference)->orWhere('name', $reference)->get();
                if ($matches->count() !== 1) {
                    $this->components->error($matches->isEmpty() ? "No OAuth client is named or numbered {$reference}." : "More than one OAuth client is named {$reference}; use its id.");

                    return self::FAILURE;
                }
                $clientIds[] = (string) $matches->first()->getKey();
            }
        }

        $attributes = [
            'name' => $this->option('name') ?? $existing?->name,
            'launch_url' => $this->option('launch-url') ?? $existing?->launch_url,
            'enabled' => $this->option('disable') ? false : ($this->option('enable') ? true : ($existing?->enabled ?? true)),
            'client_ids' => array_values(array_unique($clientIds)),
        ];
        if ($existing === null) {
            $attributes = ['key' => $key, ...$attributes];
        }

        try {
            $validated = Validator::make($attributes, SaveRegisteredApplicationRequest::rulesFor($existing === null))->validate();
            $saved = $registry->save(null, $validated, $existing, 'console');
        } catch (ValidationException $failure) {
            foreach ($failure->errors() as $messages) {
                foreach ($messages as $message) {
                    $this->components->error($message);
                }
            }

            return self::FAILURE;
        }

        $this->components->info(($existing === null ? 'Registered ' : 'Updated ').$key.'.');
        $this->show($saved);

        return self::SUCCESS;
    }

    private function show(RegisteredApplication $application): void
    {
        $this->table(['Key', 'Name', 'Launch URL', 'Enabled', 'OAuth clients'], [[
            $application->key,
            $application->name,
            $application->launch_url,
            $application->enabled ? 'yes' : 'no',
            $application->clients->map(fn (PassportClient $client): string => "{$client->name} ({$client->getKey()})")->implode(', ') ?: 'none',
        ]]);
    }
}
