# Deployment branding

One provider codebase supports separately branded deployments. Generic defaults remain unchanged until `AUTH_BRANDING_ENABLED=true`. Branding belongs to trusted deployment configuration, not OAuth clients, query parameters, uploaded HTML, or user preferences.

Example server configuration (synthetic values):

```dotenv
APP_NAME="Example Identity"
APP_URL=https://id.example.test
AUTH_BRANDING_ENABLED=true
AUTH_BRANDING_LOGO_LIGHT=/branding/logo-light.svg
AUTH_BRANDING_LOGO_DARK=/branding/logo-dark.svg
AUTH_BRANDING_FAVICON=/branding/favicon.ico
AUTH_BRANDING_STYLESHEET=/branding/theme.css
```

Supply these files privately in `public/branding/`. They are ignored by Git and preserved by both deployment jobs' guarded `rsync --delete` operations. A deployment that packages branding separately must copy its approved assets into that directory after application transfer, and verify the files are served with the correct MIME types. Refresh Laravel's configuration cache after changing server environment configuration. This feature does not provision hosts or deploy assets.

Only root-relative `/branding/` paths are accepted. Each path segment permits letters, digits, underscores and hyphens; extensions are restricted to image types for logos/icons and `.css` for stylesheets. External URLs, query strings, fragments, encoded paths and traversal are ignored. Files are maintained by deployment operators: there is no asset-upload endpoint, inline SVG inclusion, custom JavaScript or HTML theme mechanism. Review SVG and CSS as trusted deployment material; omit scripts, remote imports, tracking and external font dependencies.

The common layout places a visible application name alongside decorative logo images, so the provider remains identifiable to assistive technology and when images fail. It covers login and the emailed-code recovery island, passkeys, account/security pages, administration and OAuth consent. Existing password forms, CSRF fields, DOM IDs and consent controls are retained. Dark mode follows the existing validated theme preference and its system fallback; the light logo is reused if a dark logo is absent. Without a logo, the application name remains visible. Invalid or missing optional asset settings simply omit that element.

The stylesheet loads after the application bundle and can override existing raw HSL CSS variables in `:root` and `.dark`, for example `--primary`, `--primary-foreground`, `--background`, `--foreground`, `--card`, `--card-foreground`, `--border` and `--ring`. Choose sufficient contrast in both themes; do not hide authentication controls or error messages. Prefer versioned filenames such as `/branding/theme-v2.css` to invalidate browser caches when replacing assets.

Recovery/sign-in mail subjects and text already use `APP_NAME`; the shared mail header also displays that name and the light logo. Mail images use the configured HTTPS `APP_URL` origin, never an incoming request host. A non-HTTPS URL, URL with credentials/query/fragment, or non-root application path omits the email logo. Mail clients need not support external CSS or dark logos: messages keep readable text and the existing verification buttons. `MAIL_FROM_NAME` and `MAIL_FROM_ADDRESS` remain explicit deployment mail settings. Do not enable additional password-reset routes solely for branding; the recovery mechanism remains emailed sign-in codes and administrator assistance.

Before enabling a deployment, check native password submission, passkeys, code requests, consent, the account page, light/dark modes and a rendered test email. Keep private marks, hostnames and deployment identifiers outside this public repository.
