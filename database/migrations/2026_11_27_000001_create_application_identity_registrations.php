<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('application_identity_registrations', function (Blueprint $table): void {
            $table->id();
            $table->string('client_id', 100);
            $table->uuid('external_id');
            $table->string('subject', 191);
            $table->string('request_digest', 64);
            $table->timestamps();
            $table->unique(['client_id', 'external_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('application_identity_registrations');
    }
};
