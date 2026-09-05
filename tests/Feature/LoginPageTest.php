<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The sign-in page is server-rendered so that email and password work without
 * JavaScript; the passkey and emailed-code islands enhance it through a fixed
 * set of element ids. These tests pin the markup contract those islands and
 * assistive technology depend on.
 */
final class LoginPageTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_login_page_renders_an_accessible_password_form(): void
    {
        $response = $this->withoutVite()->get('/login');

        $response->assertOk()
            ->assertSee('<title>Sign in</title>', false)
            ->assertSee('<main', false)
            ->assertSee('<h1', false)
            ->assertSee('autocomplete="username webauthn"', false)
            ->assertSee('autocomplete="current-password"', false)
            ->assertSee('id="password-login"', false)
            ->assertSee('id="password-login-form"', false)
            ->assertSee('id="forgot-password"', false)
            ->assertSee('id="password-toggle"', false)
            ->assertSee('id="passkey-login-mount"', false)
            ->assertSee('id="email-code-login-mount"', false)
            ->assertSee('name="robots" content="noindex, nofollow, noarchive"', false)
            ->assertDontSee('<details', false)
            ->assertDontSee('Development only');
    }

    public function test_a_failed_password_login_flashes_the_email_but_never_the_password(): void
    {
        $user = User::factory()->create([
            'user_role' => 'user',
            'password' => bcrypt('synthetic-password'),
        ]);

        $this->from('/login')
            ->post('/login', [
                'email' => $user->email,
                'password' => 'not-the-password',
                'remember' => '1',
            ])
            ->assertRedirect('/login')
            ->assertSessionHasErrors('email')
            ->assertSessionHasInput('email', $user->email)
            ->assertSessionHasInput('remember', '1')
            ->assertSessionMissing('_old_input.password');

        $this->assertGuest();
    }

    public function test_the_login_page_restores_the_email_and_explains_a_failed_attempt(): void
    {
        $user = User::factory()->create([
            'user_role' => 'user',
            'password' => bcrypt('synthetic-password'),
        ]);

        // Inspecting the session on the POST response would consume the flash,
        // so this test only looks at what the following page render shows.
        $this->from('/login')->post('/login', [
            'email' => $user->email,
            'password' => 'not-the-password',
            'remember' => '1',
        ]);

        $this->withoutVite()->get('/login')
            ->assertOk()
            ->assertSee('role="alert"', false)
            ->assertSee('That email and password don&#039;t match.', false)
            ->assertSee('value="'.e($user->email).'"', false)
            ->assertSee('aria-invalid="true"', false)
            ->assertSee('aria-describedby="login-error"', false)
            ->assertSeeInOrder(['id="remember"', 'value="1"', 'checked'], false)
            ->assertDontSee('Invalid credentials');
    }

    public function test_a_successful_password_login_redirects_home(): void
    {
        $user = User::factory()->create([
            'user_role' => 'user',
            'password' => bcrypt('synthetic-password'),
        ]);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'synthetic-password',
        ])->assertRedirect('/');

        $this->assertAuthenticatedAs($user);
    }

    public function test_the_welcome_page_offers_sign_in_to_guests(): void
    {
        $this->withoutVite()->get('/')
            ->assertOk()
            ->assertSee('href="'.route('login').'"', false)
            ->assertSee('Sign in');
    }

    public function test_the_developer_login_block_only_renders_locally(): void
    {
        $this->app['env'] = 'local';

        $this->withoutVite()->get('/login')
            ->assertOk()
            ->assertSee('Development only')
            ->assertSee('action="'.route('login.dev.by-id').'"', false);
    }
}
