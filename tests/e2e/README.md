# End-to-end validation

Run against a disposable Supabase project or isolated local stack. Never reset a shared development or production database.

1. Create a standard Supabase migration and copy `sql/install.sql` into it.
2. Add DBA migrations based on `sql/templates/permissions.sql` and `sql/templates/roles.sql`.
3. Add an application table and reviewed policies based on `sql/templates/protect_table.sql`.
4. Apply migrations and run `tests/pgtap`.
5. Exercise both SDKs with two tenants and at least four users: owner, `all`, `own`, and outsider.

Required cases include cross-tenant CRUD denial, cross-scope denial, `own` row filtering, `all` access, suspended/removed membership denial, role escalation denial, DBA-only role mutation, invitation expiry/revocation/replay, immutable tenant/scope keys, and concurrent invitation acceptance.

The committed `fixtures.sql` is illustrative setup, not a production seed and not a substitute for the behavioral cases above.
