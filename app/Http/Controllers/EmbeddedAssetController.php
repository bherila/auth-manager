<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Support\Mount;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

/**
 * The package's built assets, below the embedded prefix (docs/embedded-mode.md#assets).
 *
 * Only Vite's hashed output under public/build/assets, by an allow-listed extension, and
 * never a path that resolves outside that directory.
 */
final class EmbeddedAssetController extends Controller
{
    private const TYPES = [
        'css' => 'text/css; charset=utf-8',
        'js' => 'text/javascript; charset=utf-8',
        'map' => 'application/json; charset=utf-8',
        'svg' => 'image/svg+xml',
        'png' => 'image/png',
        'webp' => 'image/webp',
        'woff' => 'font/woff',
        'woff2' => 'font/woff2',
    ];

    public function __invoke(string $file): BinaryFileResponse
    {
        $directory = realpath(Mount::packagePath('public/build/assets'));
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $path = $directory === false ? false : realpath($directory.'/'.$file);

        abort_if(
            $path === false || ! isset(self::TYPES[$extension])
                || ! str_starts_with($path, $directory.DIRECTORY_SEPARATOR) || ! is_file($path),
            404,
        );

        return response()->file($path, [
            'Content-Type' => self::TYPES[$extension],
            'Cache-Control' => 'public, max-age=31536000, immutable',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
