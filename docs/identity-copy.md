# Copying identities to another instance

`identity:export` and `identity:import` move selected people from one instance to another
with their subjects unchanged. Use them when an application moves to a new dedicated
instance and the people it already knows must keep signing in to the same accounts.

Relying applications bind their accounts to `(provider key, subject)`, and the subject is the
users-table id. A copy is only useful if every subject arrives unchanged, and it is only safe
if the receiving instance can never later give one of those subjects, or any other subject
the sending instance used, to somebody else.

## What is copied, and what is not

| Copied | Not copied, and why |
| --- | --- |
| id (the subject), name, email, email verification time | **Passkeys.** They are bound to the sending instance's RP ID and cannot be relabelled. People enrol again on the receiving instance. |
| password hash, unchanged | **Sessions and remember tokens.** They belong to the sending host and its application key. |
| roles (`user_role`), including provider `admin` | **OAuth codes, access and refresh tokens.** They were issued by the sending instance's keys for its clients. |
| disabled state (`disabled_at`) | **OAuth client grants.** They name the sending instance's clients; grant the receiving instance's clients with `--grant-client`. |
| last sign-in time, created and updated times | **Audit history, tombstones, invitations, email codes, password-reset tokens.** They describe events on the sending instance. |

Deleted people are never copied: export refuses a subject that is soft-deleted or tombstoned on
the sending instance, and import refuses a subject that is soft-deleted or tombstoned on the
receiving one.

## The document

`identity:export` prints one JSON document to standard output:

```json
{
  "format": "auth-manager.identity-copy",
  "version": 1,
  "next_id_floor": 36,
  "users": [
    { "id": 1, "name": "…", "email": "person@example.test", "email_verified_at": "…",
      "password": "$2y$…", "user_role": "admin,user", "disabled_at": null,
      "last_login_date": "…", "created_at": "…", "updated_at": "…" }
  ]
}
```

`next_id_floor` is above every identifier the sending instance has used: its users-table
sequence, its highest id including soft-deleted rows, and its highest tombstoned subject.

The document contains password hashes. Stream it from one host to the other instead of
saving it; export refuses to print to an interactive terminal unless `--allow-terminal` is
passed.

## Running a copy

Copy into a fresh instance **before anyone is created on it**. A person created there first
takes the lowest ids, and the import then refuses the document as conflicting.

```sh
# Dry run: reports the plan and writes nothing.
ssh source.example.test 'cd ~/provider && php artisan identity:export --subject=1 --subject=7' \
  | ssh target.example.test 'cd ~/provider && php artisan identity:import'

# Apply, granting the receiving instance's client to everyone who may sign in.
ssh source.example.test 'cd ~/provider && php artisan identity:export --subject=1 --subject=7' \
  | ssh target.example.test 'cd ~/provider && php artisan identity:import --apply --grant-client=<client id>'
```

Import reports `users created N, unchanged N`, `grants created N` and the sequence move. It:

- refuses the whole document, writing nothing, when any subject already exists with different
  details, any address belongs to a different subject, any subject was deleted on the receiving
  instance, or the receiving instance already holds any other subject (a person or a tombstone)
  below `next_id_floor`, since that person would inherit the sender's bindings;
- raises the users identifier sequence to `next_id_floor` (or `--next-id-at-least`, if higher)
  **before writing anyone**, so nothing created on the receiving instance meanwhile can take a
  subject the sender used. On MySQL and MariaDB this is `ALTER TABLE … AUTO_INCREMENT`; if it
  fails, the command reports why and writes nothing;
- then creates the missing people and the requested grants in one transaction, with one
  `identity_copied_in` audit row per person.

Running the same document again after a successful apply reports every person unchanged,
creates nothing and leaves the sequence alone. Sign-in time and `updated_at` are not compared,
so a person who has already signed in on the receiving instance still counts as unchanged.
A person whose name, address, password, roles or disabled state changed on either side since
the copy is reported as a conflict; settle it by hand rather than re-copying.

`--grant-client` accepts only active OAuth clients on the receiving instance and grants them to
copied people who may sign in (the `user` or `admin` role, not disabled).

## After the copy

- People sign in with their existing passwords. Passkeys must be enrolled again.
- The sending instance still holds the same people. Disabling or deleting someone there no
  longer affects the receiving instance, and the reverse; retire the application's client on
  the sending instance once it no longer signs in there.
- Engine coverage: SQLite runs in the default test suite; the MariaDB sequence path runs in the
  `mariadb` PHPUnit group (`phpunit.mariadb.xml`, the **MariaDB engine tests** CI job).
