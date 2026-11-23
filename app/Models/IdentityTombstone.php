<?php

namespace BWH\AuthManager\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class IdentityTombstone extends Model
{
    protected $guarded = [];

    /**
     * The subject relying applications knew the deleted identity by. `subject` is the deleted
     * account's row id; a tombstone the previous release wrote while `provider_subject` was being
     * added carries only that, which was then also its subject.
     */
    public function providerSubject(): string
    {
        $subject = $this->getAttribute('provider_subject');

        return is_string($subject) && $subject !== '' ? $subject : (string) $this->getAttribute('subject');
    }

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
