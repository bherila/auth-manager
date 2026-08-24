{{-- Blocking theme init, shared by every layout. Resolves the theme before
     first paint and exposes window.bwhTheme for toggles. The preference is
     shared across *.bherila.net (games.bherila.net etc.) via a `theme` cookie
     (values: system|light|dark) on Domain=.bherila.net; localStorage mirrors
     it and is the fallback where that cookie can't be set (local dev). Keep
     the cookie contract in sync with the games repo's layouts/game.blade.php. --}}
<script @cspNonce>
    (function () {
        try {
            var d = document.documentElement;
            var media = window.matchMedia('(prefers-color-scheme: dark)');
            var read = function () {
                var match = document.cookie.match(/(?:^|;\s*)theme=(dark|light|system)(?:;|$)/);
                return (match && match[1]) || localStorage.getItem('theme') || 'system';
            };
            var apply = function (theme) {
                var isDark = theme === 'dark' || (theme === 'system' && media.matches);
                d.classList.toggle('dark', isDark);
            };
            var save = function (theme) {
                try {
                    localStorage.setItem('theme', theme);
                } catch (error) {
                    // Theme still changes for this page when storage is unavailable.
                }
                var host = location.hostname;
                if (host === 'bherila.net' || host.endsWith('.bherila.net')) {
                    document.cookie = 'theme=' + theme + '; domain=.bherila.net; path=/; max-age=31536000; samesite=lax'
                        + (location.protocol === 'https:' ? '; secure' : '');
                }
            };
            window.bwhTheme = { read: read, apply: apply, save: save };
            apply(read());
            media.addEventListener('change', function () { apply(read()); });
        } catch (error) {
            // The system color scheme remains the fallback when storage is unavailable.
        }
    })();
</script>
