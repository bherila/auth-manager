<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('directory_imports', function (Blueprint $table): void {
            $table->char('checksum', 64)->primary();
            $table->json('report');
            $table->timestamp('created_at');
        });
    }

    public function down(): void
    {
        // The receipt prevents replay from overwriting a directory used after cutover.
    }
};
