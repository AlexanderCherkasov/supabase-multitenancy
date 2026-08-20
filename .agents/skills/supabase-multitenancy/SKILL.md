---
name: supabase-multitenancy
description: >-
  Expert skill for designing, implementing, and maintaining multi-tenant database architectures,
  DBA-managed RBAC roles, and Row-Level Security (RLS) on Supabase using supabase-multitenancy.
  Trigger whenever creating SaaS apps, organizations, tenants, project scopes, invitations,
  or multi-tenant RLS policies in PostgreSQL.
---

# Supabase Multitenancy & RBAC Skill

Use this skill whenever you need to design, generate, or modify multi-tenant schemas, RBAC authorization, or RLS policies using the `supabase-multitenancy` package.

---

## 🎯 When to Activate This Skill

- Building multi-tenant B2B / SaaS applications on Supabase / PostgreSQL.
- Designing tenant namespaces, project/workspace scopes, memberships, and invitations.
- Implementing RBAC with fine-grained row access control (`own` vs `all`).
- Writing robust, performant Row-Level Security (RLS) policies without recursive loops or dynamic SQL.

---

## ⛔ Absolute Guardrails for AI Agents

1. **Schema Encapsulation**: ALL multitenancy tables and implementation routines belong strictly in private schema `multitenancy`. Client RPCs and RLS helpers are thin wrappers in exposed schema `api`; **NEVER expose `multitenancy` or place package objects in `public`.**
2. **DBA-Managed Roles**: Roles and permissions are migration-owned data (`insert into multitenancy.permissions`, `insert into multitenancy.roles`). Tenant owners and admins can assign existing roles to members, but **NEVER generate API endpoints or client code that allows tenant admins to create or alter role definitions**.
3. **No Dynamic SQL in Role Tables**: Never store function names in role table columns. Use the clean contract: role permissions specify `'own'` or `'all'`, and the application RLS policy defines what `'own'` means for each table.
4. **No Service-Role Bypass in User Routes**: Always execute user queries with the user's authenticated Supabase client (JWT). The database RLS policies enforce tenant isolation automatically.
5. **Key Immutability**: Always attach the trigger `api.enforce_protected_keys_immutable()` on scoped business tables to prevent cross-tenant row transfers.

---

## 🛠️ Step-by-Step Implementation Procedure

### 1. Base Installation
Ensure `sql/install.sql` is applied as the core migration:
```bash
supabase migration new install_multitenancy
# Paste sql/install.sql into the migration file
```

### 2. Declare Permissions (DBA Migration)
```sql
insert into multitenancy.permissions (key, description) values
  ('<resource>.read',   'Read access'),
  ('<resource>.create', 'Create access'),
  ('<resource>.update', 'Update access'),
  ('<resource>.delete', 'Delete access')
on conflict (key) do update set description = excluded.description;
```

### 3. Define Roles & Access Levels (`own` vs `all`)
```sql
do $$
declare
  v_viewer uuid;
  v_editor uuid;
  v_manager uuid;
begin
  -- Viewer: own read
  insert into multitenancy.roles (key, name, description)
  values ('viewer', 'Viewer', 'Read own records') returning id into v_viewer;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_viewer, id, 'own' from multitenancy.permissions where key = '<resource>.read';

  -- Editor: own read, create, update
  insert into multitenancy.roles (key, name, description)
  values ('editor', 'Editor', 'Manage own records') returning id into v_editor;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_editor, id, 'own' from multitenancy.permissions
  where key in ('<resource>.read', '<resource>.create', '<resource>.update');

  -- Manager: all access (tenant or scope wide)
  insert into multitenancy.roles (key, name, description)
  values ('manager', 'Manager', 'Full control over resources') returning id into v_manager;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_manager, id, 'all' from multitenancy.permissions
  where key in ('<resource>.read', '<resource>.create', '<resource>.update', '<resource>.delete');
end $$;
```

### 4. Create Business Tables
```sql
create table public.<resources> (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  scope_id uuid null,
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint fk_<resources>_scope foreign key (tenant_id, scope_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

create index idx_<resources>_tenant_scope on public.<resources>(tenant_id, scope_id);

-- Enforce key immutability on update
create trigger trg_<resources>_protect
  before update on public.<resources>
  for each row execute function api.enforce_protected_keys_immutable('scope_id');

alter table public.<resources> enable row level security;
```

### 5. Generate Standard RLS Policies

```sql
-- SELECT (Read)
create policy "<resources>_select" on public.<resources>
for select to authenticated
using (
  case api.access_level(tenant_id, '<resource>.read', array[scope_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);

-- INSERT (Create)
create policy "<resources>_insert" on public.<resources>
for insert to authenticated
with check (
  author_id = auth.uid()
  and api.has_access(tenant_id, '<resource>.create', array[scope_id], 'own')
);

-- UPDATE (Edit)
create policy "<resources>_update" on public.<resources>
for update to authenticated
using (
  case api.access_level(tenant_id, '<resource>.update', array[scope_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
)
with check (
  case api.access_level(tenant_id, '<resource>.update', array[scope_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);

-- DELETE (Delete - Managers & Owners only)
create policy "<resources>_delete" on public.<resources>
for delete to authenticated
using (
  api.has_access(tenant_id, '<resource>.delete', array[scope_id], 'all')
);
```

---

## 💻 Client SDK Usage Cheatsheet

```ts
import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-multitenancy";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const mt = createMultitenancyClient(supabase);

// 1. Create Tenant
const { tenant_id } = await mt.createTenant({ slug: "acme", name: "Acme Corp" });

// 2. Create Scope
const { scope_id } = await mt.scopes.create(tenant_id, { kind: "project", key: "p1", name: "Project 1" });

// 3. Invite Member
await mt.invitations.create(tenant_id, {
  email: "dev@acme.com",
  grants: [{ role_id: editorRoleId, scope_id }]
});

// 4. Check UI Permissions
const canDelete = await mt.can(tenant_id, "documents.delete", [scope_id]);

// 5. Query Data (Transparent RLS)
const { data } = await supabase.from("documents").select("*").eq("tenant_id", tenant_id);
```
