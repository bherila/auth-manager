<?php

namespace App\Http\Middleware;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\Invitations\ApplicationActorAssertionVerifier;
use App\Services\Invitations\ApplicationInvitationRefused;
use App\Services\OAuthClientGrantService;
use App\Support\ApplicationInvitationKeys;
use App\Support\ApplicationInvitations;
use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Who is asking, for the application-requested invitation endpoints, in this order:
 *
 * 1. a client credentials access token (no person) carrying exactly `invitations:admit`;
 * 2. its client is a confidential sign-in client of an enabled registration listed in
 *    `AUTH_MANAGER_APPLICATION_INVITATIONS`, with at least one public key configured;
 * 3. an actor assertion signed with one of that application's keys, issued by that client, for
 *    this exact URL and body, not seen before;
 * 4. the actor it names is an active provider account with a current grant to that client.
 *
 * The client, its registration and the actor are handed to the controller as request attributes.
 */
class AuthenticateApplicationInvitationRequest
{
    public const CLIENT = 'application_invitation_client';

    public const APPLICATION = 'application_invitation_application';

    public const ACTOR = 'application_invitation_actor';

    public function __construct(
        private readonly ResourceServer $server,
        private readonly ApplicationInvitations $invitations,
        private readonly ApplicationInvitationKeys $keys,
        private readonly OAuthClientGrantService $grants,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        try {
            [$client, $application, $actor] = $this->authenticate($request);
        } catch (ApplicationInvitationRefused $refused) {
            return $refused->render();
        }
        $request->attributes->add([self::CLIENT => $client, self::APPLICATION => $application, self::ACTOR => $actor]);

        $response = $next($request);
        // Create and resend answers carry an invitation link, which is a bearer credential.
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    /**
     * @return array{0: PassportClient, 1: RegisteredApplication, 2: User}
     *
     * @throws ApplicationInvitationRefused
     */
    private function authenticate(Request $request): array
    {
        $clientId = $this->clientId($request);
        $client = PassportClient::query()->find($clientId);
        $application = $client instanceof PassportClient ? $this->invitations->applicationFor($client) : null;
        if (! $application instanceof RegisteredApplication) {
            throw new ApplicationInvitationRefused('application_not_enabled', 403, 'This client may not request invitations.');
        }
        $publicKeys = $this->publicKeys($application->key);
        if ($publicKeys === []) {
            throw new ApplicationInvitationRefused('application_not_enabled', 403, 'This client may not request invitations.');
        }

        $assertion = $request->headers->get(ApplicationActorAssertionVerifier::HEADER);
        if (! is_string($assertion) || $assertion === '') {
            throw new ApplicationInvitationRefused('invalid_actor_assertion', 401, 'A valid actor assertion is required.');
        }
        $claims = $this->verifier()->verify($assertion, $clientId, $this->audience($request), $request->getContent(), $publicKeys);

        $actor = User::query()->whereKey($claims['sub'])->first();
        if (! $actor instanceof User || (string) $actor->getKey() !== $claims['sub'] || ! $actor->canLogin()
            || ! $this->grants->allows($claims['sub'], $clientId)) {
            throw new ApplicationInvitationRefused('actor_not_eligible', 403, 'The actor cannot sign in to this application.');
        }

        return [$client, $application, $actor];
    }

    /**
     * The client of a valid client credentials token carrying exactly the invitation scope.
     *
     * @throws ApplicationInvitationRefused
     */
    private function clientId(Request $request): string
    {
        try {
            $token = AccessToken::fromPsrRequest($this->server->validateAuthenticatedRequest((new PsrHttpFactory)->createRequest($request)));
        } catch (OAuthServerException) {
            throw new ApplicationInvitationRefused('invalid_token', 401, 'A valid client credentials access token is required.',
                headers: ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
        }
        $clientId = $token->oauth_client_id;
        // A person's token is never the application acting as itself. The signed subject of a
        // client credentials token is empty or the client; the stored token has no person.
        if (! is_string($clientId) || $clientId === ''
            || ! in_array($token->oauth_user_id, [null, '', $clientId], true)
            || Passport::token()->newQuery()->whereKey($token->oauth_access_token_id)->whereNull('user_id')->doesntExist()) {
            throw new ApplicationInvitationRefused('invalid_token', 401, 'A valid client credentials access token is required.',
                headers: ['WWW-Authenticate' => 'Bearer error="invalid_token"']);
        }
        // Exactly this scope: `*` does not stand in for it.
        if (! in_array(ApplicationInvitations::SCOPE, (array) $token->oauth_scopes, true)) {
            throw new ApplicationInvitationRefused('insufficient_scope', 403, 'The access token does not carry the '.ApplicationInvitations::SCOPE.' scope.',
                headers: ['WWW-Authenticate' => 'Bearer error="insufficient_scope", scope="'.ApplicationInvitations::SCOPE.'"']);
        }

        return $clientId;
    }

    /**
     * @return array<string, string> PEM public keys by key id
     *
     * @throws ApplicationInvitationRefused
     */
    private function publicKeys(string $application): array
    {
        try {
            return $this->keys->publicKeys($application);
        } catch (InvalidArgumentException) {
            throw self::misconfigured();
        }
    }

    /** The exact URL the assertion must name: this provider's issuer and the request path. */
    private function audience(Request $request): string
    {
        return rtrim((string) config('auth-manager.issuer'), '/').'/'.$request->path();
    }

    private function verifier(): ApplicationActorAssertionVerifier
    {
        try {
            $connection = DB::connection(config('application-invitations.nonce_connection'));
        } catch (Throwable) {
            throw new ApplicationInvitationRefused('replay_storage_unavailable', 503, 'The request could not be checked for replay. Try again later.');
        }

        return new ApplicationActorAssertionVerifier(new DatabaseNonceStore($connection));
    }

    private static function misconfigured(): ApplicationInvitationRefused
    {
        return new ApplicationInvitationRefused('invalid_configuration', 503, 'Invitations are not configured correctly for this application.');
    }
}
