<?php

namespace App\Support;

final class DeploymentBranding
{
    public function enabled(): bool
    {
        return config('branding.enabled') === true;
    }

    /** Only deployment-owned root-relative files, never browser or client input. */
    public function asset(string $key): ?string
    {
        $extensions = match ($key) {
            'logo_light', 'logo_dark' => ['svg', 'png', 'webp', 'jpg', 'jpeg'],
            'favicon' => ['ico', 'svg', 'png'],
            'stylesheet' => ['css'],
            default => [],
        };
        $path = config('branding.'.$key);
        if (! $this->enabled() || ! is_string($path)
            || ! preg_match('~\A/branding/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.[a-z]+\z~D', $path)
            || ! in_array(pathinfo($path, PATHINFO_EXTENSION), $extensions, true)) {
            return null;
        }

        return $path;
    }

    public function emailLogo(): ?string
    {
        $path = $this->asset('logo_light');
        $base = config('app.url');
        $parts = is_string($base) ? parse_url($base) : false;
        if ($path === null || ! is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || ! in_array($parts['path'] ?? '', ['', '/'], true)) {
            return null;
        }

        return rtrim($base, '/').$path;
    }
}
