<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class RegisteredApplication extends Model
{
    /** Registry key format, shared by the administration form and delegated access configuration. */
    public const KEY_PATTERN = '/^[a-z][a-z0-9-]*$/D';

    public const KEY_MAX_LENGTH = 64;

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
