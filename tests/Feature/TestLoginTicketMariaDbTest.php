<?php

namespace Tests\Feature;

use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\TestLoginTicket;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use BWH\AuthManager\Services\TestLoginTickets;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

#[Group('mariadb')]
class TestLoginTicketMariaDbTest extends TestCase
{
    public function test_competing_connections_can_consume_a_ticket_only_once(): void
    {
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->assertTrue(function_exists('pcntl_fork'));
        $this->artisan('migrate:fresh')->assertSuccessful();
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Synthetic Application', ['https://app.example.test/callback'])->fresh();
        config(['auth-manager.test_logins.ticket_clients' => [(string) $client->id]]);
        RegisteredApplication::create(['key' => 'synthetic', 'name' => 'Synthetic', 'launch_url' => 'https://app.example.test', 'enabled' => true])->clients()->attach($client->id);
        $user = User::factory()->make(['email' => 'synthetic@example.test', 'user_role' => 'user', 'password' => 'synthetic-password']);
        $user->forceFill(['is_test_login' => true, 'test_login_expires_at' => now('UTC')->addHour()])->save();
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $ticket = app(TestLoginTickets::class)->issue($client, $user->providerSubject(), 'synthetic-password', [
            'client_id' => (string) $client->id, 'redirect_uri' => 'https://app.example.test/callback', 'response_type' => 'code',
            'state' => str_repeat('a', 40), 'code_challenge' => str_repeat('b', 43), 'code_challenge_method' => 'S256',
        ]);
        DB::disconnect();
        $workers = [];
        foreach ([1, 2] as $worker) {
            $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
            $this->assertNotFalse($pair);
            $pid = pcntl_fork();
            $this->assertNotSame(-1, $pid);
            if ($pid === 0) {
                fclose($pair[0]);
                fread($pair[1], 1);
                try {
                    DB::reconnect();
                    app(TestLoginTickets::class)->inspect($ticket['token'], true);
                    fwrite($pair[1], 'consumed');
                } catch (HttpException $failure) {
                    fwrite($pair[1], $failure->getStatusCode() === 403 ? 'refused' : 'unexpected');
                } catch (\Throwable) {
                    fwrite($pair[1], 'unexpected');
                }
                fclose($pair[1]);
                exit(0);
            }
            fclose($pair[1]);
            stream_set_timeout($pair[0], 20);
            $workers[] = [$pid, $pair[0]];
        }
        foreach ($workers as [, $socket]) {
            fwrite($socket, 'G');
        }
        $results = [];
        foreach ($workers as [$pid, $socket]) {
            $results[] = stream_get_contents($socket);
            fclose($socket);
            pcntl_waitpid($pid, $status);
            $this->assertTrue(pcntl_wifexited($status));
            $this->assertSame(0, pcntl_wexitstatus($status));
        }
        sort($results);
        $this->assertSame(['consumed', 'refused'], $results);
        DB::reconnect();
        $this->assertNotNull(TestLoginTicket::sole()->used_at);
    }
}
