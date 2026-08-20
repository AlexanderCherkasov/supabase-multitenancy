# Threat Model

## Assets and trust boundaries

Protected assets are tenant business rows, membership and role state, invitation tokens, and audit history. Authenticated users and tenant administrators are untrusted with respect to other tenants. Consumer migration authors and service-role holders are trusted. JWT identity is used only to identify the caller; live database state is authoritative for authorization.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Cross-tenant row access | Tenant-aware RLS, active membership checks, tenant foreign keys |
| Cross-scope access | Composite tenant/scope FK and per-scope coverage in `access_level()` |
| `own` to `all` escalation | Strict access lattice and level-aware grant/invitation checks |
| Tenant-created role explosion | No public role mutation API; role profiles are DBA migration data |
| Tenant-selected privileged code | No function names in RBAC data; direct application policy calls only |
| Moving rows between tenants/scopes | Generated immutable-key trigger plus `UPDATE` `USING`/`WITH CHECK` |
| Stale JWT authorization | Roles and memberships are read from live tables |
| Invitation theft | 256-bit raw token, SHA-256 at rest, email match, expiry, revoke, row lock |
| Invitation replay ambiguity | Token hash retained; same-user accept is idempotent; terminal states remain observable |
| Auth-trigger collision | Package-specific trigger name; consumer triggers are not dropped |
| Audit loss on user deletion | Actor UUID is retained without an `auth.users` foreign key |
| Private API bypass | `multitenancy` is not exposed; client grants target only reviewed `api` wrappers |
| Migration tampering | Consumer-vendored fresh v0.3 baseline, reviewed release manifest and source control |

## Residual risks

Application predicates can still be incorrect, slow, or intentionally over-broad. They execute once per candidate row and require consumer review and indexing. Tenant owners are fully trusted within their tenant. A leaked service-role key bypasses RLS. Static source checks cannot prove live grants, ownership, or policy behavior; release validation must include a local Supabase database test.

## Explicit non-goals

This package does not provide billing entitlements, organization discovery, policy authoring from untrusted runtime data, token delivery, upgrade compatibility with v0.2, or protection from a compromised database owner/service-role environment.
