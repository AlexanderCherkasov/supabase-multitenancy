# 🚀 SaaS Starter: Multi-Tenant Documents Example

A complete, step-by-step example demonstrating multi-tenancy, scoped project workspaces, and RBAC with `own` vs `all` row-level access control.

---

## Architecture Overview

```
                  ┌───────────────────────────────┐
                  │          Acme Corp            │
                  │         (tenant_id)           │
                  └──────────────┬────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 │                               │
        ┌────────▼────────┐             ┌────────▼────────┐
        │ Marketing Scope │             │  Finance Scope  │
        │   (scope_id)    │             │   (scope_id)    │
        └────────┬────────┘             └────────┬────────┘
                 │                               │
       ┌─────────▼─────────┐           ┌─────────▼─────────┐
       │     Documents     │           │     Documents     │
       │ (Marketing Team)  │           │  (Finance Team)   │
       └───────────────────┘           └───────────────────┘
```

---

## Step 1: Run Permissions & Roles Migration

Apply [`01_permissions_and_roles.sql`](file:///Users/alexander/dev/supabase-tenant-rbac/examples/1-saas-starter-documents/01_permissions_and_roles.sql):

- Registers permissions: `documents.read`, `documents.create`, `documents.update`, `documents.delete`.
- Seeds 3 standard role profiles:
  - **`viewer`**: `documents.read` with `own` access level.
  - **`editor`**: `documents.read` (`own`), `documents.create` (`own`), `documents.update` (`own`).
  - **`manager`**: `documents.read` (`all`), `documents.create` (`all`), `documents.update` (`all`), `documents.delete` (`all`).

---

## Step 2: Create Documents Table & RLS Policies

Apply [`02_documents_table_and_rls.sql`](file:///Users/alexander/dev/supabase-tenant-rbac/examples/1-saas-starter-documents/02_documents_table_and_rls.sql):

- Creates `public.documents` with `tenant_id`, `project_id`, and `author_id`.
- Attaches the immutability trigger `api.enforce_protected_keys_immutable('project_id')`.
- Enforces strict RLS policies:
  - **Read (`SELECT`)**:
    ```sql
    using (
      case api.access_level(tenant_id, 'documents.read', array[project_id])
Apply [`01_permissions_and_roles.sql`](file:///Users/alexander/dev/supabase-multitenancy/examples/1-saas-starter-documents/01_permissions_and_roles.sql):

```bash
psql $DATABASE_URL -f examples/1-saas-starter-documents/01_permissions_and_roles.sql
```

---

## Step 2: Application Schema & RLS Policies

Apply [`02_documents_table_and_rls.sql`](file:///Users/alexander/dev/supabase-multitenancy/examples/1-saas-starter-documents/02_documents_table_and_rls.sql):

```bash
psql $DATABASE_URL -f examples/1-saas-starter-documents/02_documents_table_and_rls.sql
```

---

## 💻 Running the Example Workflow

See [`workflow_example.ts`](file:///Users/alexander/dev/supabase-multitenancy/examples/1-saas-starter-documents/workflow_example.ts) or [`workflow_example.py`](file:///Users/alexander/dev/supabase-multitenancy/examples/1-saas-starter-documents/workflow_example.py) for the complete integration flow.
