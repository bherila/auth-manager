<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    public function up(): void
    {
        if (! Schema::connection($this->getConnection())->hasTable('registered_applications')) {
            Schema::connection($this->getConnection())->create('registered_applications', function (Blueprint $table): void {
                $table->id();
                $table->string('key', 64)->unique();
                $table->string('name', 255);
                $table->string('launch_url', 2048);
                $table->boolean('enabled')->default(false);
                $table->timestamps();
            });
        }

        if (! Schema::connection($this->getConnection())->hasTable('registered_application_clients')) {
            Schema::connection($this->getConnection())->create('registered_application_clients', function (Blueprint $table): void {
                $table->id();
                $table->foreignId('registered_application_id')->constrained()->cascadeOnDelete();
                $table->uuid('oauth_client_id')->unique();
                $table->foreign('oauth_client_id')->references('id')->on('oauth_clients')->cascadeOnDelete();
            });
        }
    }

    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists('registered_application_clients');
        Schema::connection($this->getConnection())->dropIfExists('registered_applications');
    }
};
