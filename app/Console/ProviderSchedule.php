<?php

namespace BWH\AuthManager\Console;

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use BWH\AuthManager\Models\InvitationAcceptanceCode;
use Closure;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/** The provider's scheduled work, on a standalone deployment's scheduler or a host's. */
final class ProviderSchedule
{
    /** @param (Closure(Closure(): mixed): mixed)|null $within runs each in-process task, e.g. inside the embedded context */
    public static function define(Schedule $schedule, ?Closure $within = null): void
    {
        $within ??= static fn (Closure $task): mixed => $task();

        $schedule->command('identities:purge-tombstones')
            ->hourly()
            ->withoutOverlapping();

        // Used actor assertion ids outlive their assertions by seconds; only expired ones are removed.
        $schedule->call(static fn () => $within(static function (): void {
            if (Schema::connection(config('application-invitations.nonce_connection'))->hasTable(DatabaseNonceStore::TABLE)) {
                (new DatabaseNonceStore(DB::connection(config('application-invitations.nonce_connection'))))->pruneExpired();
            }
        }))->name('application-invitations:prune-nonces')->hourly()->withoutOverlapping();

        // Invitation acceptance codes live minutes; expired ones, used or not, are removed.
        $schedule->call(static fn () => $within(static fn () => InvitationAcceptanceCode::pruneExpired()))
            ->name('application-invitations:prune-codes')->hourly()->withoutOverlapping();
    }
}
