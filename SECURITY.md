# Security Policy

## Supported version

Only the latest pre-release version is supported. Version 0.1 used a dynamic row-check design and must not be deployed.

## Reporting

Report suspected tenant-isolation, privilege-escalation, invitation-token, or RPC authorization issues privately to the maintainers. Do not include production tokens, JWTs, database dumps, or personal data. Include the package version, PostgreSQL/Supabase version, reproduction SQL, expected result, and observed result.

## Security invariants

- `multitenancy` is not an exposed API schema.
- App tables containing tenant data have RLS enabled and no bypass grants for client roles.
- Every protected row has a tenant foreign key; scoped rows use a composite tenant/scope foreign key.
- Role data contains permission keys and `own|all` levels only.
- Role definitions and role permissions are DBA-managed and have no public mutation RPC.
- No tenant-controlled SQL identifier is dynamically executed by a privileged function.
- Custom row predicates are application-owned, schema-qualified, reviewed migrations and remain `SECURITY INVOKER`.
- Every `SECURITY DEFINER` function uses `set search_path = ''` and explicitly qualified relations.
- Function execution is revoked from `public`/`anon` unless anonymous use is intentional.
- Raw invitation tokens are returned only on create/resend and never logged or persisted.
- Tenant and scope keys on protected rows cannot change through normal updates.

## Operational guidance

Use the service-role key only on trusted servers. Review the vendored package SQL and every consumer RLS migration before applying them. Test owner, member, suspended, removed, cross-tenant, cross-scope, `own`, `all`, invitation replay, and escalation cases against a disposable local Supabase database. Treat changes to RLS, helper functions, grants, trigger ownership, and `auth.users` integration as security-sensitive changes.
