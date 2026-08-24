<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $twoFactorTable = config('bherila-auth.two_factor.table', 'auth_two_factor_attempts');

        if (! Schema::hasTable($twoFactorTable)) {
            Schema::create($twoFactorTable, function (Blueprint $table) {
                $table->id();
                $table->foreignId('user_id')->constrained()->cascadeOnDelete();
                $table->string('token', 128)->unique();
                $table->string('code', 6);
                $table->boolean('is_used')->default(false);
                $table->boolean('is_suspicious')->default(false);
                $table->string('ip_address', 45)->nullable();
                $table->text('user_agent')->nullable();
                $table->timestamp('expires_at');
                $table->timestamps();
                $table->index(['user_id', 'is_used']);
                $table->index('expires_at');
            });
        }

        $passkeysTable = config('bherila-auth.passkeys.table', 'auth_passkeys');

        if (! Schema::hasTable($passkeysTable)) {
            Schema::create($passkeysTable, function (Blueprint $table) {
                $table->id();
                $table->foreignId('user_id')->constrained()->cascadeOnDelete();
                $table->string('credential_id', 2048);
                $table->string('credential_id_hash', 64)->nullable()->unique();
                $table->text('public_key');
                $table->unsignedBigInteger('counter')->default(0);
                $table->string('aaguid', 64)->nullable();
                $table->string('name')->default('Passkey');
                $table->json('transports')->nullable();
                $table->timestamp('last_used_at')->nullable();
                $table->timestamps();
                $table->index('user_id');
            });
        }
    }

    public function down(): void
    {
        if (! config('bherila-auth.migrations.drop_tables_on_rollback', false)) {
            return;
        }

        Schema::dropIfExists(config('bherila-auth.passkeys.table', 'auth_passkeys'));
        Schema::dropIfExists(config('bherila-auth.two_factor.table', 'auth_two_factor_attempts'));
    }
};
