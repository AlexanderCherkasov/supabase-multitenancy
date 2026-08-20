# Package migrations

Migrations are applied in numeric order and form the version 0.3 fresh
pre-production baseline.

1. Base schema, settings, and package metadata (`001_base.sql`)
2. Profiles, tenants, scopes, memberships, and package-owned auth trigger (`002_identities.sql`)
3. Permission catalog, DBA-managed role profiles, `own|all` access levels, and assignments (`003_rbac.sql`)
4. Invitation lifecycle and foreign tenant protection trigger (`004_invitations.sql`)
5. Append-only audit log (`005_audit.sql`)
6. RLS lockdown, access level resolution, and immutability trigger (`006_authorize.sql`)
7. Self-service tenant creation & permission check helper (`007_rpc_tenant.sql`)
8. Keyset pagination cursor encoding/decoding (`008_rpc_cursor.sql`)
9. Metadata discovery & keyset-paginated context (`009_rpc_context.sql`)
10. Invitation preview & acceptance (`010_rpc_invitations.sql`)
11. Tenant administration & audit helper (`011_admin_tenant.sql`)
12. Scope administration (`012_admin_scope.sql`)
13. Member grant assignment, suspension, and removal (`013_admin_member.sql`)
14. Invitation lifecycle administration (`014_admin_invitation.sql`)
15. Central admin router & grant validation (`015_admin_router.sql`)
16. `api` boundary wrappers, schema lockdown, and package version (`016_api_boundary.sql`)

`sql/install.sql` is generated from these files for fresh installs. Consumers
copy it into a normal, immutable Supabase migration. v0.3 intentionally has no
upgrade path from v0.2: reset disposable older installs before applying this
fresh baseline. The package tables and implementations remain private in
`multitenancy`; client RPCs and RLS helpers are exposed only through `api`.
