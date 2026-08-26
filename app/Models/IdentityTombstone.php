<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class IdentityTombstone extends Model
{
    protected $guarded = [];

    /**
     * @return HasMany<IdentityTombstoneClient, $this>
     */
    public function clients(): HasMany
    {
        return $this->hasMany(IdentityTombstoneClient::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'subject' => 'integer',
            'tombstoned_at' => 'immutable_datetime',
            'purge_after' => 'immutable_datetime',
            'provider_purged_at' => 'immutable_datetime',
            'unacknowledged_clients' => 'array',
        ];
    }
}
