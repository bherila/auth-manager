<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Browsers a person has confirmed with an emailed code, which may skip the code on a later
 * password sign-in (see BWH\AuthManager\Services\TrustedDevices).
 *
 * Only a hash of each device token is stored, so a copy of this table can't be replayed as a
 * cookie. A row also records the account's credential version, and stops counting as soon as
 * that advances.
 *
 * A new table the previous release never reads, so it runs unchanged against it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('trusted_devices', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->char('token_hash', 64)->unique();
            $table->unsignedBigInteger('credential_version');
            $table->string('user_agent', 512)->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('trusted_devices');
    }
};
