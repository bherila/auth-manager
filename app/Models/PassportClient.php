<?php

namespace App\Models;

use BWH\Auth\OAuth\Server\ResourceClient;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Scope;

class PassportClient extends ResourceClient
{
    /**
     * The registered consumers are first-party applications. The explicit
     * sign-in click happens in the client before this authorization request.
     *
     * @param  Scope[]  $scopes
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        // ResourceClient returns false for a dynamically registered client.
        // Static first-party clients retain this provider's established consent
        // behavior rather than becoming prompts merely by adopting RFC 8707.
        return $this->firstParty();
    }
}
