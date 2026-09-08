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

## Packaging approved assets

`scripts/branding/package.py` is the reusable, standard-library-only build helper (Python 3.10+). It accepts explicit files; it has no deployment-specific asset names, hostnames or source repository assumptions:

```sh
python3 /reviewed-engine/scripts/branding/package.py \
  --identity /build/provider \
  --logo-light /approved-brand/light.svg \
  --logo-dark /approved-brand/dark.svg \
  --favicon /approved-brand/favicon.ico \
  --theme-css /approved-brand/design-system.css
```

Run this only against an **unserved build directory** after the provider source and build assets are present. It requires `config/branding.php` and a real `public/` directory, and creates the absent `public/branding/` directory with four fixed outputs: `logo-light.svg`, `logo-dark.svg`, `favicon.ico` and `theme.css`. Existing output is never overwritten. Empty or missing files, aliases through symlinks, incorrect image extensions and invalid theme values fail before output creation; an I/O failure removes newly created partial output so the build can be retried. Filesystem inputs and output must remain under the trusted build operator's control throughout the operation.

SVG/ICO inputs are approved assets, copied byte-for-byte, **not sanitized uploads**. Operators must review their actual contents and media types, including SVG scripts and external references. The stylesheet helper is a restricted value extractor, not a CSS parser: it reads the first standalone `:root` and `.dark` blocks, requires exactly one declaration for each supported color token, and emits only raw HSL triples (hue 0–360; saturation/lightness 0–100%). It also takes the first `--font-sans` declaration from a top-level `:root`, `@theme` or `@theme inline` block as the global default, allowing plain ASCII family names with balanced single/double quotes and comma separators. Comments, unrelated rules, imports and component-level font overrides are not emitted. Nested theme blocks, CSS expressions, duplicate required tokens and unsupported font syntax must be normalized in the approved input before packaging.

The helper does not set environment configuration, acquire assets, build the application, upload artifacts, provision hosts or activate a release. Private orchestration supplies approved inputs and keeps its asset mapping, secrets and target configuration private. Invocation failures report only a generic error category, without copying source paths or file contents into CI logs.

Pin and verify the helper's source commit before invoking it. Keep this **engine pin separate from the application revision** so an older compatible application can be deployed without downgrading the packager. A trusted orchestration step must verify both checkout SHAs before running their code; the helper cannot establish its own provenance. Application revisions predating the branding hooks are intentionally rejected. No existing deployment workflow is switched by adding this helper.

Run its synthetic tests with `python3 -m unittest discover -s tests/branding`; they also run in `composer ci:check`. Tests generate temporary assets and styles rather than depending on any deployment's branding.
