<?php

namespace Tests\Feature;

use App\Models\User;
use App\Support\DeploymentBranding;
use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Tests\TestCase;

class DeploymentBrandingTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.key' => 'base64:'.base64_encode(str_repeat('x', 32))]);
        $this->withoutVite();
    }

    private function branding(): void
    {
        config([
            'app.name' => 'Example Identity', 'app.url' => 'https://id.example.test',
            'branding.enabled' => true,
            'branding.logo_light' => '/branding/logo-light.svg',
            'branding.logo_dark' => '/branding/logo-dark.svg',
            'branding.favicon' => '/branding/favicon.ico',
            'branding.stylesheet' => '/branding/theme.css',
        ]);
    }

    public function test_generic_defaults_ignore_browser_branding_and_preserve_native_login_contract(): void
    {
        $this->get('/login?branding=enabled&logo=https://untrusted.example.test/logo.svg')->assertOk()
            ->assertSee('<title>Sign in</title>', false)->assertDontSee('untrusted.example.test')
            ->assertDontSee('provider-brand flex')->assertSee('id="password-login-form"', false)
            ->assertSee('name="_token"', false)->assertSee('id="passkey-login-mount"', false)
            ->assertSee('id="email-code-login-mount"', false);
    }

    public function test_title_escapes_the_deployment_name_exactly_once(): void
    {
        $this->branding();
        config(['app.name' => 'Rock & Roll <Identity>']);
        $this->get('/login')->assertOk()
            ->assertSee('<title>Sign in — Rock &amp; Roll &lt;Identity&gt;</title>', false)->assertDontSee('&amp;amp;', false);
        $this->get('/')->assertOk()->assertSee('<title>Rock &amp; Roll &lt;Identity&gt;</title>', false);
    }

    public function test_branded_login_passkeys_and_consent_share_name_theme_and_safe_assets(): void
    {
        $this->branding();
        $this->get('/login')->assertOk()->assertSee('<title>Sign in — Example Identity</title>', false)
            ->assertSee('/branding/logo-light.svg')->assertSee('/branding/logo-dark.svg')
            ->assertSee('dark:hidden')->assertSee('dark:block')->assertSee('alt=""', false)
            ->assertSee('/branding/favicon.ico')->assertSee('/branding/theme.css')
            ->assertSee('id="password-login-form"', false)->assertSee('name="password"', false);
        $user = User::factory()->create(['user_role' => 'user']);
        $this->actingAs($user)->get('/settings/passkeys')->assertOk()->assertSee('Example Identity')->assertSee('/branding/logo-light.svg');
        $request = Request::create('/oauth/authorize', 'GET', ['state' => 'example-state']);
        $client = new Client(['id' => 'example-client', 'name' => 'Example Application']);
        $html = view('oauth.authorize', ['client' => $client, 'request' => $request, 'authToken' => 'synthetic-token'])->render();
        $this->assertStringContainsString('/branding/logo-dark.svg', $html);
        $this->assertStringContainsString('Example Identity', $html);
        $this->assertStringContainsString('name="auth_token"', $html);
        $this->assertStringContainsString('name="_token"', $html);
        config(['branding.logo_dark' => null]);
        $this->assertSame(2, substr_count($this->get('/login')->getContent(), 'src="/branding/logo-light.svg"'));
    }

    public function test_assets_reject_remote_encoded_traversal_and_executable_paths_and_escape_name(): void
    {
        $this->branding();
        $branding = app(DeploymentBranding::class);
        foreach (['https://untrusted.example.test/logo.svg', '//untrusted.example.test/logo.svg', '/branding/../logo.svg', '/branding/%2e%2e/logo.svg', '/branding/logo.svg?x=1', '/branding/logo.svg#x', '/branding/logo.js', '/branding/logo.svg" onload="x', '/branding/a\\b.svg'] as $path) {
            config(['branding.logo_light' => $path]);
            $this->assertNull($branding->asset('logo_light'));
        }
        config(['branding.stylesheet' => '/branding/theme.js', 'app.name' => '<script>example</script>']);
        $this->assertNull($branding->asset('stylesheet'));
        $this->get('/login')->assertDontSee('<script>example</script>', false)->assertSee('&lt;script&gt;example&lt;/script&gt;', false);
        $this->get('/')->assertOk()->assertDontSee('<script>example</script>', false);
    }

    public function test_recovery_mail_uses_deployment_name_and_https_local_logo_without_request_host(): void
    {
        $this->branding();
        $user = User::factory()->make(['name' => 'Example Person', 'email' => 'person@example.test']);
        $attempt = new TwoFactorAttempt(['code' => '123456']);
        $mail = new TwoFactorLoginMail($user, $attempt, 'https://id.example.test/confirm', 'https://id.example.test/report', config('app.name'));
        $this->assertStringContainsString('Example Identity', $mail->envelope()->subject);
        $html = $mail->render();
        $this->assertStringContainsString('https://id.example.test/branding/logo-light.svg', $html);
        $this->assertStringContainsString('Example Identity', $html);
        foreach (['http://id.example.test', 'https://user@id.example.test', 'https://id.example.test/path', 'https://id.example.test?query=1'] as $url) {
            config(['app.url' => $url]);
            $this->assertNull(app(DeploymentBranding::class)->emailLogo());
        }
    }
}
