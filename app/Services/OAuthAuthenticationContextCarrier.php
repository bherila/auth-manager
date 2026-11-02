<?php

namespace BWH\AuthManager\Services;

/** Hands a code's or refresh lineage's authentication context to the token issued from it, within a request. */
class OAuthAuthenticationContextCarrier
{
    /** @var array<string, array{auth_time: int|null, amr: string|null, acr: string|null}> */
    private array $contexts = [];

    /** @param  array{auth_time: mixed, amr: mixed, acr: mixed}  $columns */
    public function carry(string $subject, array $columns): void
    {
        $this->contexts[$subject] = [
            'auth_time' => $columns['auth_time'] === null ? null : (int) $columns['auth_time'],
            'amr' => is_string($columns['amr']) ? $columns['amr'] : null,
            'acr' => is_string($columns['acr']) ? $columns['acr'] : null,
        ];
    }

    /** @return array{auth_time: int|null, amr: string|null, acr: string|null} */
    public function columnsFor(string $subject): array
    {
        return $this->contexts[$subject] ?? ['auth_time' => null, 'amr' => null, 'acr' => null];
    }
}
