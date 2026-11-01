<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Http\Middleware\AuthenticateApplicationInvitationRequest;
use BWH\AuthManager\Models\AccessInvitation;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\Invitations\AccessInvitationService;
use BWH\AuthManager\Services\Invitations\ApplicationInvitationRefused;
use BWH\AuthManager\Services\Invitations\IssuedInvitation;
use BWH\AuthManager\Services\Invitations\RequestingClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use JsonException;

/**
 * Admission invitations an application requests for itself: create, resend and revoke.
 *
 * The caller is authenticated by {@see AuthenticateApplicationInvitationRequest}. Everything here
 * acts only on the calling client's own invitations, and the answer to a create is the same whether
 * or not the address has an account here: nothing is looked up. The link is returned every time.
 * The contract is docs/application-invitations.md.
 */
class ApplicationInvitationController extends Controller
{
    public function __construct(private readonly AccessInvitationService $invitations) {}

    public function store(Request $request): JsonResponse
    {
        $body = $this->body($request, ['email']);
        $validator = Validator::make($body, ['email' => ['required', 'string', 'email', 'max:255']]);
        if ($validator->fails()) {
            throw new ApplicationInvitationRefused('invalid_request', 422, 'The request is not valid.', ['errors' => $validator->errors()->toArray()]);
        }
        $this->requireMail();

        $issued = $this->invitations->create($request, $this->actor($request), $this->application($request), (string) $body['email'],
            ['application_admin' => false, 'workspaces' => []], $this->via($request));

        return $this->issued($issued, 201);
    }

    public function resend(Request $request, string $invitation): JsonResponse
    {
        $this->body($request, []);
        $found = $this->find($request, $invitation);
        $this->requireMail();

        return $this->issued($this->invitations->resend($request, $this->actor($request), $found, $this->application($request), $this->via($request)), 200);
    }

    public function revoke(Request $request, string $invitation): JsonResponse
    {
        $this->body($request, []);
        $revoked = $this->invitations->revoke($request, $this->actor($request), $this->find($request, $invitation), $this->via($request));

        return response()->json(['invitation' => ['id' => $revoked->getKey(), 'status' => $revoked->status()]]);
    }

    /**
     * The JSON object the assertion's body hash covers, with no members but these.
     *
     * @param  list<string>  $allowed
     * @return array<string, mixed>
     *
     * @throws ApplicationInvitationRefused
     */
    private function body(Request $request, array $allowed): array
    {
        try {
            $decoded = json_decode($request->getContent(), false, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $decoded = null;
        }
        if (! $decoded instanceof \stdClass) {
            throw new ApplicationInvitationRefused('invalid_request', 422, 'The body must be a JSON object.');
        }
        $body = (array) $decoded;
        $unknown = array_values(array_diff(array_keys($body), $allowed));
        if ($unknown !== []) {
            throw new ApplicationInvitationRefused('invalid_request', 422, 'The request is not valid.',
                ['errors' => array_fill_keys($unknown, ['This field is not accepted.'])]);
        }

        return $body;
    }

    /**
     * One of the calling client's own invitations; any other id, another application's or another
     * client's included, gets the same answer.
     *
     * @throws ApplicationInvitationRefused
     */
    private function find(Request $request, string $id): AccessInvitation
    {
        $invitation = AccessInvitation::query()
            ->whereKey((int) $id)
            ->where('application', $this->application($request)->key)
            ->where('requesting_client_id', $this->via($request)->clientId)
            ->first();
        if (! $invitation instanceof AccessInvitation) {
            throw new ApplicationInvitationRefused('invitation_not_found', 404, 'No such invitation for this client.');
        }

        return $invitation;
    }

    /** @throws ApplicationInvitationRefused */
    private function requireMail(): void
    {
        if (! AccessInvitationService::mailDelivers()) {
            throw new ApplicationInvitationRefused('mail_unavailable', 503, 'Email is not configured to deliver on this provider, so invitations cannot be sent.');
        }
    }

    private function issued(IssuedInvitation $issued, int $status): JsonResponse
    {
        $invitation = $issued->invitation;

        return response()->json(['invitation' => [
            'id' => $invitation->getKey(),
            'status' => $invitation->status(),
            'expires_at' => $invitation->expires_at->copy()->utc()->format('Y-m-d\TH:i:s\Z'),
            'link' => $issued->link,
            'email_sent' => $issued->sent,
        ]], $status);
    }

    private function actor(Request $request): User
    {
        return $request->attributes->get(AuthenticateApplicationInvitationRequest::ACTOR);
    }

    private function application(Request $request): RegisteredApplication
    {
        return $request->attributes->get(AuthenticateApplicationInvitationRequest::APPLICATION);
    }

    private function via(Request $request): RequestingClient
    {
        /** @var PassportClient $client */
        $client = $request->attributes->get(AuthenticateApplicationInvitationRequest::CLIENT);

        return new RequestingClient((string) $client->getKey());
    }
}
