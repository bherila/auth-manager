<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class IdentityTombstoneClient extends Model
{
    protected $guarded = [];

    /**
     * @return BelongsTo<IdentityTombstone, $this>
     */
    public function tombstone(): BelongsTo
    {
        return $this->belongsTo(IdentityTombstone::class, 'identity_tombstone_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'acknowledged_at' => 'immutable_datetime',
        ];
    }
}
