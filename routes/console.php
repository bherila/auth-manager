<?php

use BWH\Auth\OAuth\DelegatedAccess\DatabaseNonceStore;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Facades\Schema;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Schedule::command('identities:purge-tombstones')
    ->hourly()
    ->withoutOverlapping();

// Used actor assertion ids outlive their assertions by seconds; only expired ones are removed.
Schedule::call(static function (): void {
    if (Schema::connection(config('application-invitations.nonce_connection'))->hasTable(DatabaseNonceStore::TABLE)) {
        (new DatabaseNonceStore(DB::connection(config('application-invitations.nonce_connection'))))->pruneExpired();
    }
})->name('application-invitations:prune-nonces')->hourly()->withoutOverlapping();
