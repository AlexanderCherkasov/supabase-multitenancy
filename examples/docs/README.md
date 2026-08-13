# Documents example

This example shows the consumer/package boundary:

1. `schema.sql` creates application-owned document tables and database constraints.
2. `custom_check_example.sql` defines an optional application-owned `SECURITY INVOKER` predicate.
3. `seed_roles.sql` is a DBA migration that defines role profiles with `own|all` permission levels.
4. `sql/templates/protect_table.sql` is copied and adapted as the final RLS migration.

Apply the package migrations first. Replace the placeholder tenant UUID in `seed_roles.sql`. Role definitions are deliberately migration-only; the public admin RPC can assign existing roles but cannot create or edit them.

The custom predicate is deliberately absent from `multitenancy.role_permissions`. Changing predicate code requires a reviewed application migration; tenant role data cannot select arbitrary SQL functions.
