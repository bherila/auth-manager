<?php

namespace App\Console\Commands;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Support\ApplicationInvitationKeys;
use App\Support\ApplicationInvitations;
use App\Support\StaticApplicationClients;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Console\Command;
use InvalidArgumentException;

/**
 * Show whether an application can request admission invitations, and allow or remove the client
 * credentials grant on its sign-in clients.
 *
 * Listing the application in AUTH_MANAGER_APPLICATION_INVITATIONS and configuring its public key
 * stay environment changes; this command only shows them. Without an option it changes nothing.
 */
class ManageApplicationInvitations extends Command
{
    protected $signature = 'auth-manager:application-invitations
        {key : The registry key, for example example-app}
        {--allow-client-credentials : Add the client_credentials grant to the application\'s confidential sign-in clients}
        {--remove-client-credentials : Remove the client_credentials grant from all of the application\'s clients}';

    protected $description = 'Show or prepare an application for admission invitations it requests';

    public function handle(ApplicationInvitations $invitations, ApplicationInvitationKeys $keys): int
    {
        $application = RegisteredApplication::query()->with('clients')->where('key', (string) $this->argument('key'))->first();
        if (! $application instanceof RegisteredApplication) {
            $this->components->error('No application is registered as '.$this->argument('key').'.');

            return self::FAILURE;
        }
        $allow = (bool) $this->option('allow-client-credentials');
        $remove = (bool) $this->option('remove-client-credentials');
        if ($allow && $remove) {
            $this->components->error('Choose --allow-client-credentials or --remove-client-credentials, not both.');

            return self::INVALID;
        }

        $eligible = new StaticApplicationClients;
        foreach ($application->clients as $client) {
            $types = (array) $client->grant_types;
            $has = in_array('client_credentials', $types, true);
            $wanted = $allow ? ($client->confidential() && $eligible->eligible($client)) : ($remove ? false : $has);
            if ($wanted === $has) {
                continue;
            }
            $client->forceFill(['grant_types' => $wanted
                ? [...$types, 'client_credentials']
                : array_values(array_diff($types, ['client_credentials']))])->save();
            AuthAuditLog::create([
                'event' => $wanted ? 'application_invitation_client_credentials_allowed' : 'application_invitation_client_credentials_removed',
                'auth_method' => 'console', 'succeeded' => true,
                'metadata' => ['application' => $application->key, 'oauth_client_id' => (string) $client->getKey()],
            ]);
            $this->components->info(($wanted ? 'Allowed' : 'Removed').' client credentials for '.$client->getKey().'.');
        }

        $keyIds = [];
        try {
            $keyIds = array_keys($keys->for($application->key));
            $keyState = $keyIds === [] ? 'none' : implode(', ', $keyIds);
        } catch (InvalidArgumentException $failure) {
            $keyState = 'invalid: '.$failure->getMessage();
        }
        $this->table(['Application', 'Registration enabled', 'Listed in AUTH_MANAGER_APPLICATION_INVITATIONS', 'Public key ids'], [[
            $application->key, $application->enabled ? 'yes' : 'no', $invitations->listedFor($application->key) ? 'yes' : 'no', $keyState,
        ]]);
        $this->table(['OAuth client', 'Confidential sign-in client', 'Client credentials', 'Can request invitations'],
            $application->clients()->get()->map(fn (PassportClient $client): array => [
                "{$client->name} ({$client->getKey()})",
                $client->confidential() && $eligible->eligible($client) ? 'yes' : 'no',
                in_array('client_credentials', (array) $client->grant_types, true) ? 'yes' : 'no',
                $invitations->applicationFor($client) !== null && $keyIds !== [] && in_array('client_credentials', (array) $client->grant_types, true) ? 'yes' : 'no',
            ])->all());

        return self::SUCCESS;
    }
}
