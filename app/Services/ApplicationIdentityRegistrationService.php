<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Models\ApplicationIdentityRegistration;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\ApplicationRegistration;
use BWH\AuthManager\Support\StaticApplicationClients;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use SensitiveParameter;

/** Creates only new people. A duplicate address never adopts an existing identity. */
final class ApplicationIdentityRegistrationService
{
    /** @param array{external_id:string,name:string,email:string,password_hash:string} $data
     * @return array{subject:string,created:bool}
     */
    public function register(PassportClient $client, #[SensitiveParameter] array $data): array
    {
        $digest = hash('sha256', json_encode($data, JSON_THROW_ON_ERROR));
        try {
            return DB::transaction(function () use ($client, $data, $digest): array {
                $receipt = ApplicationIdentityRegistration::query()->where('client_id', $client->getKey())
                    ->where('external_id', $data['external_id'])->lockForUpdate()->first();
                if ($receipt instanceof ApplicationIdentityRegistration) {
                    return $this->replay($client, $receipt, $digest);
                }
                // Include deleted rows: reusing their address cannot resurrect a retired account.
                abort_if(User::withTrashed()->whereRaw('LOWER(email) = ?', [$data['email']])->exists(), 409, 'Identity registration conflicts with existing state.');
                $grantClients = $this->grantClients($client);
                $user = new User;
                // The input has already been validated as a bounded password hash; preserve it.
                $user->setRawAttributes(['name' => $data['name'], 'email' => $data['email'],
                    'password' => $data['password_hash'], 'user_role' => 'user', 'email_verified_at' => null,
                    'credential_version' => 0, 'disabled_at' => null]);
                $user->save();
                foreach ($grantClients as $grantClient) {
                    app(OAuthClientGrantService::class)->grant((string) $user->getKey(), $grantClient);
                }
                ApplicationIdentityRegistration::create(['client_id' => $client->getKey(), 'external_id' => $data['external_id'],
                    'subject' => $user->providerSubject(), 'request_digest' => $digest]);
                AuthAuditLog::create(['user_id' => $user->getKey(), 'event' => 'identity_registered_by_application',
                    'auth_method' => 'application', 'succeeded' => true,
                    'metadata' => ['client_id' => (string) $client->getKey(), 'external_id' => $data['external_id']]]);

                return ['subject' => $user->providerSubject(), 'created' => true];
            }, 3);
        } catch (QueryException $exception) {
            if (! in_array((string) $exception->getCode(), ['23000', '23505'], true)) {
                throw $exception;
            }
            // An identical concurrent create may have won the unique constraint.
            $receipt = ApplicationIdentityRegistration::query()->where('client_id', $client->getKey())
                ->where('external_id', $data['external_id'])->first();
            abort_unless($receipt instanceof ApplicationIdentityRegistration, 409, 'Identity registration conflicts with existing state.');

            return $this->replay($client, $receipt, $digest);
        }
    }

    /** @return array{subject:string,created:bool} */
    private function replay(PassportClient $client, ApplicationIdentityRegistration $receipt, string $digest): array
    {
        abort_unless(hash_equals((string) $receipt->request_digest, $digest), 409, 'Identity registration conflicts with existing state.');
        $subject = (string) $receipt->subject;
        $user = User::query()->whereProviderSubject($subject)->first();
        abort_unless($user instanceof User && hash_equals($user->providerSubject(), $subject) && $user->canLogin()
            && app(OAuthClientGrantService::class)->allows((string) $user->getKey(), (string) $client->getKey()),
            409, 'The registered identity is no longer available.');

        return ['subject' => $subject, 'created' => false];
    }

    /** Only deployment configuration may add coarse grants; the request never selects them.
     * @return list<string>
     */
    private function grantClients(PassportClient $caller): array
    {
        $application = (new ApplicationRegistration)->applicationFor($caller);
        abort_if($application === null, 403);
        $rules = config('auth-manager.application_registration.additional_client_grants', []);
        abort_unless(is_array($rules), 503, 'Registration grants are not configured correctly.');
        $extra = $rules[$application->key] ?? [];
        abort_unless(is_array($extra) && array_is_list($extra) && count($extra) <= 16
            && count(array_filter($extra, static fn ($id): bool => is_string($id) && $id !== '')) === count($extra), 503,
            'Registration grants are not configured correctly.');
        $ids = array_values(array_unique([(string) $caller->getKey(), ...$extra]));
        $clients = PassportClient::query()->whereIn('id', $ids)->get();
        abort_unless($clients->count() === count($ids) && $clients->every(static fn (PassportClient $client): bool => $client->confidential() && (new StaticApplicationClients)->eligible($client)), 503,
            'Registration grants are not configured correctly.');

        return $ids;
    }
}
