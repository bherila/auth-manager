<?php

namespace Tests\Feature;

use Tests\TestCase;

/**
 * This application publishes its own copy of the shared package's configuration.
 * `mergeConfigFrom` merges only the top level, so a nested array declared here replaces
 * the package's version of that array outright rather than being combined with it. A key
 * the package adds in a later release therefore resolves to null here, silently, with no
 * error at any point — the feature simply behaves as though it were never configured.
 *
 * This asserts the published copy still declares everything the package does.
 */
class AuthConfigCompletenessTest extends TestCase
{
    public function test_every_shared_array_the_published_config_overrides_is_complete(): void
    {
        $packagePath = base_path('vendor/bherila/auth-laravel/config/bherila-auth.php');
        $this->assertFileExists($packagePath);

        $package = require $packagePath;
        $published = require config_path('bherila-auth.php');

        $missing = $this->missingKeys($package, $published);

        $this->assertSame([], $missing, sprintf(
            "config/bherila-auth.php overrides a shared array but omits: %s.\n".
            'A nested array here replaces the package default entirely, so those keys resolve to null.',
            implode(', ', $missing),
        ));
    }

    /**
     * Keys the package declares inside an array the published config also declares.
     *
     * A top-level key the published config omits entirely is not a problem: the shallow
     * merge supplies the package's value wholesale. The hazard is only for an array that
     * is present in both, where the published version wins outright.
     *
     * @param  array<string, mixed>  $package
     * @param  array<string, mixed>  $published
     * @return list<string>
     */
    private function missingKeys(array $package, array $published, string $prefix = ''): array
    {
        $missing = [];

        foreach ($package as $key => $value) {
            if (is_int($key) || ! array_key_exists($key, $published)) {
                continue;
            }

            $path = $prefix === '' ? (string) $key : "{$prefix}.{$key}";

            if (! is_array($value) || $value === [] || array_is_list($value)) {
                continue;
            }

            if (! is_array($published[$key])) {
                continue;
            }

            foreach (array_keys($value) as $childKey) {
                if (is_int($childKey)) {
                    continue;
                }

                if (! array_key_exists($childKey, $published[$key])) {
                    $missing[] = "{$path}.{$childKey}";
                }
            }

            $missing = array_merge($missing, $this->missingKeys($value, $published[$key], $path));
        }

        return array_values(array_unique($missing));
    }
}
