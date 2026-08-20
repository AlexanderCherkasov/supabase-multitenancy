# 🤖 AI Agent Implementation & Design Guide

> **Target Audience**: AI Coding Assistants (Antigravity, Cursor, Claude Code, GitHub Copilot, Codex) and System Architects designing multi-tenant SaaS applications with Supabase.

This guide provides deterministic, step-by-step instructions, schema patterns, and guardrails for implementing multi-tenant data architecture and Row-Level Security (RLS) using `supabase-multitenancy`.

---

## 🧭 Core Architectural Philosophy for Agents

When a user asks you to build a multi-tenant application, SaaS platform, B2B tool, or organization-based RBAC on Supabase:

1. **DO NOT invent custom RLS helper functions or ad-hoc tenant loops.**
2. **Keep package internals private.** All package tables and implementation routines live in `multitenancy`; client RPCs and RLS helpers use the exposed `api` wrappers. Never expose `multitenancy` through the Data API.
3. **DO NOT store SQL function names in role tables.** Use the `own` vs `all` contract and compose predicates in RLS migrations.
4. **DO NOT use `service_role` in frontend or user requests.** All user queries run via authenticated JWT through PostgREST; the database RLS policies enforce isolation automatically.

---

## 📐 Standard 5-Step Agent Implementation Workflow

When generating code or migrations for a multi-tenant feature:

```
Step 1: Install Core SQL Package (sql/install.sql)
   ↓
Step 2: Declare Application Permissions (multitenancy.permissions)
   ↓
Step 3: Define DBA Role Profiles with 'own' vs 'all' (multitenancy.roles)
   ↓
Step 4: Create Business Tables with Tenant/Scope Foreign Keys & Triggers
   ↓
Step 5: Attach Canonical RLS Policies with api.access_level() / api.has_access()
```

---

### Step 1: Database Baseline Migration

Ensure `sql/install.sql` is applied in the target database. Client-facing routines are available under the exposed `api` schema; implementation tables remain under private `multitenancy`.

---

### Step 2: Declare Granular Permissions

Always declare permissions in database migrations using dot-notation: `<resource>.<action>`.

```sql
-- Migration: <timestamp>_permissions.sql
insert into multitenancy.permissions (key, description) values
  ('projects.read',    'View projects within tenant or scope'),
  ('projects.create',  'Create new projects'),
  ('projects.update',  'Edit existing projects'),
  ('projects.delete',  'Delete projects'),
  ('documents.read',   'Read documents'),
  ('documents.write',  'Create and edit documents'),
  ('documents.delete', 'Delete documents')
on conflict (key) do update set description = excluded.description;
```

---

### Step 3: Define DBA Role Profiles (`own` vs `all`)

Map permissions to roles using strictly `'own'` or `'all'`:
- **`own`**: Access restricted to rows owned, assigned, or shared with the user.
- **`all`**: Access granted to all rows in the tenant (or within the assigned `scope_id`).

```sql
-- Migration: <timestamp>_roles.sql
do $$
declare
  v_viewer uuid;
  v_editor uuid;
  v_manager uuid;
begin
  -- 1. Viewer Role
  insert into multitenancy.roles (key, name, description)
  values ('viewer', 'Viewer', 'Read-only access to own/assigned resources')
  returning id into v_viewer;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_viewer, id, 'own'
  from multitenancy.permissions where key in ('projects.read', 'documents.read');

  -- 2. Editor Role
  insert into multitenancy.roles (key, name, description)
  values ('editor', 'Editor', 'Author and edit own resources')
  returning id into v_editor;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_editor, id, 'own'
  from multitenancy.permissions where key in ('projects.read', 'documents.read', 'documents.write');

  -- 3. Manager Role
  insert into multitenancy.roles (key, name, description)
  values ('manager', 'Manager', 'Full control over all resources in tenant/scope')
  returning id into v_manager;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_manager, id, 'all'
  from multitenancy.permissions where key in (
    'projects.read', 'projects.create', 'projects.update', 'projects.delete',
    'documents.read', 'documents.write', 'documents.delete'
  );
end $$;
```

These are global roles: omit `tenant_id`. For an exceptional DBA-only role
restricted to one tenant, insert a non-NULL `tenant_id` and a distinct global
`key`; never create it through `api.admin` or an SDK method.

---

### Step 4: Business Table Creation Pattern

Every multi-tenant business table MUST include:
1. `tenant_id uuid not null references multitenancy.tenants(id) on delete cascade`
2. Optional `project_id uuid null` (or any scope column) with foreign key:
   `foreign key (tenant_id, project_id) references multitenancy.scopes(tenant_id, id) on delete restrict`
3. `author_id uuid not null default auth.uid() references auth.users(id)`
4. Key immutability trigger: `api.enforce_protected_keys_immutable('project_id')`
5. Fast composite index on `(tenant_id, project_id)`

```sql
-- Migration: <timestamp>_create_documents.sql
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid null,
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint fk_documents_scope foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

create index idx_documents_tenant_scope on public.documents(tenant_id, project_id);
create index idx_documents_author on public.documents(author_id);

-- Enforce key immutability (prevents cross-tenant moving)
create trigger trg_documents_protect
  before update on public.documents
  for each row execute function api.enforce_protected_keys_immutable('project_id');

alter table public.documents enable row level security;
```

---

### Step 5: Canonical RLS Policy Templates for Agents

When generating RLS policies, use these exact battle-tested patterns:

#### 1. SELECT (Read Policy)
```sql
create policy "documents_select" on public.documents
for select to authenticated
using (
  case api.access_level(tenant_id, 'documents.read', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);
```

#### 2. INSERT (Create Policy)
```sql
create policy "documents_insert" on public.documents
for insert to authenticated
with check (
  author_id = auth.uid()
  and api.has_access(tenant_id, 'documents.write', array[project_id], 'own')
);
```

#### 3. UPDATE (Edit Policy with `USING` and `WITH CHECK`)
```sql
create policy "documents_update" on public.documents
for update to authenticated
using (
  case api.access_level(tenant_id, 'documents.write', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
)
with check (
  case api.access_level(tenant_id, 'documents.write', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);
```

#### 4. DELETE (Delete Policy - Managers & Owners Only)
```sql
create policy "documents_delete" on public.documents
for delete to authenticated
using (
  api.has_access(tenant_id, 'documents.delete', array[project_id], 'all')
);
```

---

## 🤝 Advanced Pattern: Custom Sharing & Collaborators

If the application requires granular sharing (e.g. sharing a document with specific users), define a `document_collaborators` table and a `SECURITY INVOKER` function, then compose it into the `own` branch:

```sql
-- 1. Helper function (MUST be SECURITY INVOKER)
create or replace function public.is_document_collaborator(
  p_document_id uuid,
  p_user_id uuid,
  p_min_level text default 'view'
)
returns boolean language sql stable security invoker as $$
  select exists (
    select 1 from public.document_collaborators
    where document_id = p_document_id
      and user_id = p_user_id
      and (p_min_level = 'view' or permission_level = 'edit')
  );
$$;

-- 2. Compose into RLS policy
create policy "documents_select_shared" on public.documents
for select to authenticated
using (
  case api.access_level(tenant_id, 'documents.read', array[project_id])
    when 'all' then true
    when 'own' then (
      author_id = auth.uid()
      or public.is_document_collaborator(id, auth.uid(), 'view')
    )
    else false
  end
);
```

---

## 💻 Client SDK Integration Patterns for Agents

### Frontend / UI Component Pattern (React / Next.js / Vue / Svelte)

```tsx
import { useEffect, useState } from "react";
import { createMultitenancyClient } from "supabase-multitenancy";
import { supabase } from "@/lib/supabaseClient";

const mt = createMultitenancyClient(supabase);

export function DocumentEditor({ tenantId, projectId, documentId }) {
  const [canDelete, setCanDelete] = useState(false);
  const [doc, setDoc] = useState(null);

  useEffect(() => {
    async function loadData() {
      // 1. Fetch document via standard PostgREST (RLS enforced automatically)
      const { data } = await supabase
        .from("documents")
        .select("*")
        .eq("id", documentId)
        .single();
      setDoc(data);

      // 2. Check UI permission for action buttons
      const allowed = await mt.can(tenantId, "documents.delete", [projectId]);
      setCanDelete(allowed);
    }
    loadData();
  }, [tenantId, projectId, documentId]);

  return (
    <div>
      <h1>{doc?.title}</h1>
      {canDelete && <button onClick={handleDelete}>Delete Document</button>}
    </div>
  );
}
```

---

## ⚠️ Anti-Patterns & Common AI Mistakes to Avoid

| ❌ Anti-Pattern | ✅ Correct Architecture |
| :--- | :--- |
| **Bypassing RLS with `supabaseAdmin` / `service_role` in user routes** | Let the user's JWT authenticate the request and let database RLS policies filter rows. |
| **Storing custom role definitions via API endpoints** | Roles and permissions are migration-owned. Use `mt.members.setGrants` to assign existing roles. |
| **Using `SECURITY DEFINER` on custom app predicates** | Custom table predicates must be `SECURITY INVOKER` to prevent privilege escalation. |
| **Modifying `tenant_id` on update** | Always attach `api.enforce_protected_keys_immutable()` trigger to prevent tenant hopping. |
| **Calling private RPCs** | Client code and RLS use exposed `api` (`create_tenant`, `can`, `context`, `context_page`, `invitation_preview`, `accept_invitation`, `admin`); never expose `multitenancy`. |

---

## 📚 Quick Reference Cheat Sheet

- **`api.create_tenant(slug, name)`**: Creates a tenant and active owner membership.
- **`api.can(tenant_id, permission, scope_ids)`**: Returns `boolean` for UI permission checks.
- **`api.context(tenant_id, section)`**: Returns an array for list sections; use `api.context_page` for a cursor page.
- **`api.access_level(tenant_id, permission, scope_ids)`**: Returns `'none' | 'own' | 'all'` inside RLS policies.
- **`api.has_access(tenant_id, permission, scope_ids, required_level)`**: Compares access level in RLS policies.
