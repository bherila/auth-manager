<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->boolean('is_test_login')->default(false);
            $table->timestamp('test_login_expires_at')->nullable();
            $table->index(['is_test_login', 'test_login_expires_at'], 'users_test_login_expiry_index');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropIndex('users_test_login_expiry_index');
            $table->dropColumn(['is_test_login', 'test_login_expires_at']);
        });
    }
};
