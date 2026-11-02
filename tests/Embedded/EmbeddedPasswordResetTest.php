<?php

namespace Tests\Embedded;

use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Sleep;

/** Self-service password reset under an embedded mount (auth-manager#112). */
final class EmbeddedPasswordResetTest extends EmbeddedTestCase
{
    protected array $environment = ['AUTH_MANAGER_ALLOW_PASSWORD_RESET' => 'true'];

    public function test_the_pages_links_and_redirects_stay_below_the_prefix(): void
    {
        Mail::fake();
        Sleep::fake();
        [$user] = $this->grantedClient('correct horse battery staple');
        // The host has an account with the same address, which a reset must never touch.
        DB::table('users')->insert(['email' => $user->email]);
        $hostAccounts = DB::table('users')->orderBy('id')->get()->all();

        $this->get('/auth/login')->assertOk()->assertSee(self::HOST.'/auth/forgot-password', false);
        $this->get('/auth/forgot-password')->assertOk()->assertSee('action="'.self::HOST.'/auth/forgot-password"', false);

        $this->post('/auth/forgot-password', ['email' => $user->email])->assertRedirect();

        $link = null;
        Mail::assertSent(PasswordResetConfirmationMail::class, function (PasswordResetConfirmationMail $mail) use (&$link): bool {
            $link = $mail->resetUrl;

            return true;
        });
        $this->assertStringStartsWith(self::HOST.'/auth/reset-password/', (string) $link);

        $this->get((string) parse_url((string) $link, PHP_URL_PATH).'?'.parse_url((string) $link, PHP_URL_QUERY))
            ->assertOk()
            ->assertSee('action="'.self::HOST.'/auth/reset-password"', false);

        $token = rawurldecode(basename((string) parse_url((string) $link, PHP_URL_PATH)));
        $this->post('/auth/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'a-new-synthetic-password',
            'password_confirmation' => 'a-new-synthetic-password',
        ])->assertRedirect(self::HOST.'/auth/login');

        $password = app(EmbeddedContext::class)->run(fn () => User::query()->findOrFail($user->getKey())->password);
        $this->assertTrue(Hash::check('a-new-synthetic-password', $password));
        $this->assertEquals($hostAccounts, DB::table('users')->orderBy('id')->get()->all());
    }

    public function test_the_host_keeps_its_own_routes_at_the_root(): void
    {
        $this->get('/forgot-password')->assertNotFound();
    }
}
