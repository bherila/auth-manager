<?php

namespace App\Services;

class OAuthCredentialGenerationContext
{
    /** @var array<string, int> */
    private array $expectedVersions = [];

    public function expect(string $subject, int $version): void
    {
        $this->expectedVersions[$subject] = $version;
    }

    public function expectedFor(string $subject): ?int
    {
        return $this->expectedVersions[$subject] ?? null;
    }
}
