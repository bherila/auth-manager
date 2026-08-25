<?php

namespace Tests\Feature;

use App\Http\Controllers\OAuthUserController;
use App\Models\User;
use App\Support\RelyingApplications;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The switcher's contents come from the OAuth clients themselves rather than a hand-kept
 * list, so what is worth pinning is the derivation: a client's home page is the origin of
 * the redirect URI it already registered, and anything that cannot yield one is not an
 * application a person can be sent to.
 */
class RelyingApplicationsTest extends TestCase
{
    use RefreshDatabase;

    private function client(string $name, string $redirectUris, bool $revoked = false): void
    {
        DB::table('oauth_clients')->insert([
            'id' => (string) Str::uuid(),
            'name' => $name,
            'secret' => 'secret',
            'redirect_uris' => $redirectUris,
            'grant_types' => json_encode(['authorization_code']),
            'revoked' => $revoked,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function test_each_client_becomes_an_application_at_its_redirect_origin(): void
    {
        $this->client('Finance', json_encode(['https://pf.example.test/oauth/callback']));

        $this->assertSame(
            [['key' => 'finance', 'name' => 'Finance', 'url' => 'https://pf.example.test']],
            (new RelyingApplications)->forSubject('1'),
        );
    }

    public function test_a_revoked_client_is_not_an_application(): void
    {
        $this->client('Retired', json_encode(['https://retired.example.test/oauth/callback']), revoked: true);

        $this->assertSame([], (new RelyingApplications)->forSubject('1'));
    }

    /**
     * A client with nowhere to send anyone — no redirect at all, one that is not absolute,
     * or a column that does not parse — is not an application. Emitting it would put a dead
     * entry in every switcher. The column is NOT NULL, so an empty list is how "none" looks.
     */
    public function test_a_client_without_an_absolute_redirect_is_skipped(): void
    {
        $this->client('Machine', json_encode([]));
        $this->client('Relative', json_encode(['/callback']));
        $this->client('Malformed', 'not json');

        $this->assertSame([], (new RelyingApplications)->forSubject('1'));
    }

    /**
     * The list rides on the identity payload so a relying application can cache it in the
     * session it is already opening, instead of calling back here to render every page.
     */
    public function test_the_identity_payload_carries_the_application_list(): void
    {
        $this->client('Finance', json_encode(['https://pf.example.test/oauth/callback']));

        $user = User::factory()->create();
        $request = Request::create('/api/oauth/user');
        $request->setUserResolver(fn (): User => $user);

        // Invoked directly rather than over HTTP: the route is guarded by `auth:api`, and
        // standing up Passport's signing keys would test its crypto rather than this payload.
        $payload = (new OAuthUserController(new RelyingApplications))($request)->getData(true);

        $this->assertSame((string) $user->getKey(), $payload['sub']);
        $this->assertSame(
            [['key' => 'finance', 'name' => 'Finance', 'url' => 'https://pf.example.test']],
            $payload['apps'],
        );
    }

    public function test_a_non_default_port_is_kept(): void
    {
        $this->client('Local', json_encode(['http://localhost:8000/oauth/callback']));

        $this->assertSame('http://localhost:8000', (new RelyingApplications)->forSubject('1')[0]['url']);
    }
}
