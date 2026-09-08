<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class RegisteredApplication extends Model
{
    protected $fillable = ['key', 'name', 'launch_url', 'enabled'];

    public function getConnectionName(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    protected function casts(): array
    {
        return ['enabled' => 'boolean'];
    }

    public function clients(): BelongsToMany
    {
        return $this->belongsToMany(PassportClient::class, 'registered_application_clients', 'registered_application_id', 'oauth_client_id');
    }
}
