# Working on Auth Manager

Read `README.md`, then the guide for the area being changed. `docs/deployment.md`
explains instance ownership and rollout; `docs/account-management-contract.md`
explains identity, application access and consumer boundaries.

## Boundaries

- This is a public repository. Use synthetic identities, reserved example domains
  and generated fixtures. Keep customer names, marks, assets, hostnames, account
  identifiers, credentials and infrastructure inventories in the operator's
  private repository or infrastructure store.
- Preserve the built-in light/dark theme. Branding is optional trusted deployment
  configuration, never client-controlled HTML, scripts, request parameters or
  OAuth registration metadata. Test defaults as well as configured overrides.
- Auth Manager owns credentials and provider identity. Applications own their
  accounts, domain data and fine-grained authorization. Provider administrator,
  OAuth client grant and application administrator are distinct permissions.
- Bind consumers by provider and subject, never by email alone. Passkeys remain
  bound to their original RP IDs; changing the RP requires new enrollment rather
  than credential rebinding. Preserve the explicit local emergency-access path.
- Put reusable deployment behavior and synthetic tests here. Operator repositories
  own their CI integration, private assets, host policy and secrets. Verify separate
  application/tooling pins before executing either checkout. Do not make upstream
  CI deploy to a customer environment as part of a generic feature.
- Treat schema migration, code activation and account cutover as separate steps.
  Execute live deployment/migration only within the user's authorized scope.
  Preserve isolated databases, signing keys, sessions and persistent storage.

## Validation and delivery

Use existing Laravel, TypeScript and component conventions. Keep changes focused.
Use CI for heavy validation: full test suites, full Pint, PHPStan, builds and
mutation/coverage runs. Run these locally only when the user explicitly requests
local execution. Keep local checks to relevant tests, file-scoped formatting,
linting and targeted browser verification; push a focused candidate promptly.
Use required CI results on the exact candidate commit as the validation gate.
Inspect mutation artifacts when an advisory green job can hide escaped mutations;
do not weaken checks or deadlines. Run scoped Python checks for touched deployment
behavior. Use isolated SQLite test databases and synthetic environment settings;
never seed tests from a live environment. This user preference supersedes older
guidance requiring full local runs.

Before publishing, run `node scripts/scan-sensitive.mjs --staged` and the full-tree
scan, and manually review the diff for disclosure. Do not weaken the scanner to
allow real deployment material.

Keep detailed procedures in `docs/` and link them from the README. Distinguish
implemented provider screens from consumer integration, and code/test success from
verified deployment. Report the exact tested release and material checks still
pending; do not claim a rollback restores database state or deleted identities.
