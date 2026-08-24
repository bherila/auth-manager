<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('user_role')->default('user')->after('password');
            $table->dateTime('last_login_date')->nullable()->after('user_role');
            $table->index('user_role', 'users_user_role_index');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropIndex('users_user_role_index');
            $table->dropColumn(['user_role', 'last_login_date']);
        });
    }
};
