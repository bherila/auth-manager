<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * How the person authenticated when a code or token was issued. Nullable and unread by
     * earlier code, so it's safe against the previous release. Existing rows stay NULL,
     * meaning unknown, which satisfies no requirement.
     */
    public function up(): void
    {
        foreach (['oauth_auth_codes', 'oauth_access_tokens'] as $name) {
            if (Schema::hasTable($name) && ! Schema::hasColumn($name, 'auth_time')) {
                Schema::table($name, function (Blueprint $table): void {
                    $table->unsignedBigInteger('auth_time')->nullable();
                    $table->string('amr', 255)->nullable();
                    $table->string('acr', 255)->nullable();
                });
            }
        }
    }

    public function down(): void
    {
        foreach (['oauth_auth_codes', 'oauth_access_tokens'] as $name) {
            if (Schema::hasTable($name) && Schema::hasColumn($name, 'auth_time')) {
                Schema::table($name, function (Blueprint $table): void {
                    $table->dropColumn(['auth_time', 'amr', 'acr']);
                });
            }
        }
    }
};
