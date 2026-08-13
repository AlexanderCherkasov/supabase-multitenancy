# supabase-tenant-rbac

A SQL-first multi-tenancy and RBAC foundation for Supabase. The database is the product: tenant namespaces, typed scopes, memberships, DBA-managed role profiles, `own|all` RLS authorization, invitations, audit events, and six versioned RPCs.

There is no package-specific CLI and no runtime JSON configuration. Consumer projects install reviewed SQL through their normal Supabase migration workflow. TypeScript and Python SDKs are optional, user-session wrappers over the public RPCs.

## Install the database package

Create a normal consumer migration with the Supabase CLI, then copy the contents of `sql/install.sql` into it:

```bash
supabase migration new install_multitenancy
```

For development from this repository, `npm run build:sql` regenerates `sql/install.sql` from the ordered files in `sql/migrations`. The `multitenancy` schema encapsulates all package tables, triggers, helper functions, and RPC entrypoints.

After the core migration, add reviewed consumer migrations based on:

- `sql/templates/settings.sql`
- `sql/templates/permissions.sql`
- `sql/templates/roles.sql`
- `sql/templates/protect_table.sql`

Permissions and role profiles are DBA-owned migration data. `anon`, `authenticated`, and `service_role` have no table privileges on `multitenancy.roles` or `multitenancy.role_permissions`. Tenant owners may assign existing roles but cannot create or edit them.

## Access model

Each role permission has one level:

- `own`: the application policy must also match `auth.uid()` or an application-owned row predicate.
- `all`: every row in the covered tenant/scope is allowed.

`multitenancy.access_level()` returns `none`, `own`, or `all` from live database state. `multitenancy.has_access()` compares the result with a required level. For multiple scopes, every scope must be covered and the weakest covered level wins.

Custom row predicates belong directly in consumer RLS migrations. Keep them `SECURITY INVOKER`; never store a function name in tenant-controlled data.

## TypeScript SDK

```bash
npm install supabase-tenant-rbac @supabase/supabase-js
```

```ts
import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-tenant-rbac";

const supabase = createClient(url, publishableKey);
const mt = createMultitenancyClient<"documents.read" | "documents.update">(supabase);

const tenant = await mt.createTenant({ slug: "acme", name: "Acme" });
const roles = await mt.roles.list(tenant.tenant_id); // read-only catalog
const allowed = await mt.can(tenant.tenant_id, "documents.read");
```

The SDK includes typed tenant, permission, role, scope, member, invitation, audit, authorization, and generic admin APIs. It deliberately exposes no role mutation method.

## Python SDK

```bash
pip install ./python
```

```python
from supabase import create_client
from supabase_multitenancy import MultitenancyClient

supabase = create_client(url, publishable_key)
mt = MultitenancyClient(supabase)

tenant = mt.create_tenant(slug="acme", name="Acme")
roles = mt.roles.list(tenant["tenant_id"])
allowed = mt.can(tenant["tenant_id"], "documents.read")
```

Both SDKs require a Supabase client carrying the current user's session. Never put a service-role or secret key in a browser, mobile application, or other untrusted client.

## Package RPC surface (`multitenancy` schema)

- `multitenancy.create_tenant(slug, name)`
- `multitenancy.can(tenant_id, permission, scope_ids)`
- `multitenancy.context(tenant_id, section, cursor, limit)`
- `multitenancy.invitation_preview(token)`
- `multitenancy.accept_invitation(token)`
- `multitenancy.admin(tenant_id, command, payload)`

All RPCs reside in the `multitenancy` schema, return `{ "api_version": 1, "data": ... }`, and are called through the SDK's schema-scoped client.

## Verification

```bash
npm run typecheck
npm test
PYTHONPATH=python/src python3 -m unittest discover -s python/tests -v
```

Run `tests/pgtap` against a disposable local Supabase database before release. See [ARCHITECTURE.md](./ARCHITECTURE.md), [SECURITY.md](./SECURITY.md), and [THREAT_MODEL.md](./THREAT_MODEL.md).
