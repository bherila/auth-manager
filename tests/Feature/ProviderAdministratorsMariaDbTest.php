<?php

namespace Tests\Feature;

use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/** Real competing connections; run only against the isolated MariaDB CI service. */
#[Group('mariadb')]
class ProviderAdministratorsMariaDbTest extends TestCase
{
    /** @return array<string, array{string}> */
    public static function competingActions(): array
    {
        return ['demote' => ['demote'], 'disable' => ['disable'], 'delete' => ['delete'], 'operator role command' => ['cli']];
    }

    #[DataProvider('competingActions')]
    public function test_competing_mutations_cannot_remove_both_recovery_administrators(string $otherAction): void
    {
        $this->assertSame('auth_manager_ci', DB::connection()->getDatabaseName());
        $this->assertContains(DB::connection()->getDriverName(), ['mysql', 'mariadb']);
        $this->assertTrue(function_exists('pcntl_fork'), 'The MariaDB CI lane requires pcntl for its concurrency test.');
        $this->artisan('migrate:fresh')->assertSuccessful();
        $first = User::factory()->create(['user_role' => 'admin']);
        $second = User::factory()->create(['user_role' => 'admin']);
        // Fork with no live inherited PDO socket, then connect independently in each worker.
        DB::disconnect();
        $workers = [];
        foreach ([[$first->id, 'demote'], [$second->id, $otherAction]] as [$id, $action]) {
            $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
            $this->assertNotFalse($pair);
            $pid = pcntl_fork();
            $this->assertNotSame(-1, $pid);
            if ($pid === 0) {
                fclose($pair[0]);
                fread($pair[1], 1);
                try {
                    DB::reconnect();
                    $user = User::findOrFail($id);
                    $request = Request::create('/api/admin/users', 'PUT');
                    $request->setLaravelSession(app('session')->driver('array'));
                    $request->session()->put(EnsureCredentialVersion::SESSION_KEY, (int) $user->credential_version);
                    $request->session()->put(RequireRecentPasskeyAuthentication::SESSION_KEY, ['user_id' => (string) $id, 'authenticated_at' => now()->timestamp]);
                    $service = app(DirectoryAdminService::class);
                    if ($action === 'demote') {
                        $service->changeAdministrator($request, $user, $user, false, app(ProviderAdministrators::class)->revision($user));
                    } elseif ($action === 'disable') {
                        $service->disable($request, $user, $user);
                    } elseif ($action === 'delete') {
                        $service->tombstone($request, $user, $user);
                    } else {
                        $exit = Artisan::call('auth-manager:user-roles', ['user' => (string) $id, '--remove' => ['admin']]);
                        fwrite($pair[1], $exit === 0 ? 'changed' : 'guarded');
                        fclose($pair[1]);
                        exit(0);
                    }
                    fwrite($pair[1], 'changed');
                } catch (ValidationException) {
                    fwrite($pair[1], 'guarded');
                } catch (\Throwable $failure) {
                    fwrite($pair[1], 'unexpected:'.$failure::class);
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
        $this->assertSame(['changed', 'guarded'], $results);
        DB::reconnect();
        $this->assertCount(1, User::all()->filter(static fn (User $user): bool => $user->canLogin() && $user->hasRole('admin')));
    }
}
