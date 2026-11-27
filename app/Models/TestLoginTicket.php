<?php

namespace BWH\AuthManager\Models;

use Illuminate\Database\Eloquent\Model;

final class TestLoginTicket extends Model
{
    protected $guarded = [];

    protected $hidden = ['token_hash', 'authorization_uri'];

    protected function casts(): array
    {
        return ['expires_at' => 'immutable_datetime', 'used_at' => 'immutable_datetime', 'credential_version' => 'integer'];
    }
}
