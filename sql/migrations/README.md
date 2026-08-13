# Package migrations

Migrations are applied in numeric order and form the version 0.2 pre-release baseline.

1. Base schema, settings, and package metadata
2. Profiles, tenants, scopes, memberships, and package-owned auth trigger
3. Permission catalog, DBA-managed role profiles, `own|all` access levels, and assignments
4. Invitation lifecycle
5. Append-only audit log
6. RLS lockdown and authorization helpers
7. Core public RPCs
8. Administrative command RPC
9. Removal of the legacy dynamic row-check surface and version finalization

`sql/install.sql` is generated from these files for fresh installs. Consumers copy it into a normal, immutable Supabase migration. Future published versions add separate append-only upgrade SQL. Because 0.2 rewrites the unpublished 0.1 draft, reset disposable 0.1 databases before installing 0.2.
