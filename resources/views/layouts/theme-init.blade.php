{{-- Blocking theme init, shared by every layout. Resolves the theme before
     first paint and exposes window.bwhTheme for toggles. The preference is
     through the validated profile/environment allow-list. localStorage mirrors
     it and is the fallback where that cookie cannot be set (local dev). --}}
<script @cspNonce>
    (function () {
        try {
            var cookieDomain = @json(config('auth-manager.theme.cookie_domain'));
            var allowedHosts = @json(config('auth-manager.theme.allowed_hosts', []));
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
                var allowed = Array.isArray(allowedHosts) && allowedHosts.some(function (allowedHost) {
                    return typeof allowedHost === 'string' && (host === allowedHost || host.endsWith('.' + allowedHost));
                });
                if (typeof cookieDomain === 'string' && cookieDomain !== '' && allowed) {
                    document.cookie = 'theme=' + theme + '; domain=' + cookieDomain + '; path=/; max-age=31536000; samesite=lax'
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
