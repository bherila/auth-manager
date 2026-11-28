<?php

namespace BWH\AuthManager\Models;

use BWH\AuthManager\Services\AccessGroupService;
use Illuminate\Database\Eloquent\Model;

/**
 * A named set of people who are granted the same applications. Membership and the group's
 * applications are expanded into ordinary `oauth_client_grants` rows by
 * {@see AccessGroupService}; sign-in never reads groups directly.
 *
 * @property int $id
 * @property string $name
 * @property string|null $description
 * @property bool $auto_join Every account created from now on joins this group (docs/default-access.md).
 */
class AccessGroup extends Model
{
    public const NAME_MAX_LENGTH = 100;

    public const DESCRIPTION_MAX_LENGTH = 500;

    protected $fillable = ['name', 'description', 'auto_join'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['auto_join' => 'boolean'];
    }
}
