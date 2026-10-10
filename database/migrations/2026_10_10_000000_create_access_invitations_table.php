<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Invitations to an application, sent by email from its access page.
 *
 * Only a SHA-256 hash of each token is stored. `access` is the application access the invitation
 * applies at acceptance; `roles_*` record what happened when it tried.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('access_invitations', function (Blueprint $table): void {
            $table->id();
            $table->string('application', 64);
            $table->string('email');
            $table->string('email_normalized');
            $table->char('token_hash', 64)->unique();
            $table->foreignId('inviter_id')->nullable()->constrained('users')->nullOnDelete();
            // The inviter's credential generation when they passed the write gate; a reset since voids the roles.
            $table->unsignedInteger('inviter_credential_version');
            $table->json('access');
            $table->timestamp('expires_at');
            $table->timestamp('last_sent_at')->nullable();
            $table->unsignedSmallInteger('send_count')->default(0);
            $table->timestamp('revoked_at')->nullable();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('accepted_at')->nullable();
            $table->foreignId('accepted_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('roles_status', 16)->nullable();
            $table->string('roles_outcome', 64)->nullable();
            $table->string('roles_request_id', 64)->nullable();
            $table->timestamp('roles_checked_at')->nullable();
            $table->timestamps();

            $table->index(['application', 'created_at']);
            $table->index('email_normalized');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('access_invitations');
    }
};
