# supabase-multitenancy

[![npm version](https://img.shields.io/npm/v/supabase-multitenancy.svg)](https://www.npmjs.com/package/supabase-multitenancy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A SQL-first multi-tenancy and RBAC foundation for **Supabase**. The database is the source of truth: tenant namespaces, hierarchical scopes, memberships, DBA-managed role profiles, `own|all` RLS authorization, invitations, audit logging, and six versioned RPCs.

- **Zero Public Schema Pollution**: All tables, functions, and triggers reside in the dedicated `multitenancy` schema.
- **SQL-First & Safe**: Roles and permissions are DBA-managed migration data. Tenant admins cannot elevate privileges.
- **`own` vs `all` Access Contract**: Express fine-grained authorization (read own rows vs read all tenant rows) with single-line SQL predicates.
- **Full SDK Support**: Typed TypeScript and Python SDKs for user-session operations and UI permission checks (`can()`).

---

## 📦 Quick Installation

### 1. Database Package (SQL Migration)

Create a new Supabase migration and paste the contents of [`sql/install.sql`](file:///Users/alexander/dev/supabase-tenant-rbac/sql/install.sql):

```bash
supabase migration new install_multitenancy
# Copy sql/install.sql into supabase/migrations/<timestamp>_install_multitenancy.sql
supabase db push
```

### 2. Client SDKs

```bash
# TypeScript / JavaScript
npm install supabase-multitenancy @supabase/supabase-js

# Python
pip install supabase-multitenancy
```

---

## 🛠️ Step-by-Step Practical Guide

### Step 1: Declare Permissions (DBA Migration)

Permissions are global capabilities defined by database migrations.

```sql
insert into multitenancy.permissions (key, description) values
  ('documents.read',   'Read documents in tenant or scope'),
  ('documents.create', 'Create new documents'),
  ('documents.update', 'Edit documents'),
  ('documents.delete', 'Delete documents')
on conflict (key) do update set description = excluded.description;
```

---

### Step 2: Define Roles with `own` vs `all` Access Levels

Roles map permissions to access levels:
- **`own`**: User can only access rows they authored (`author_id = auth.uid()`).
- **`all`**: User can access all rows across the tenant or assigned scope.

```sql
do $$
declare
  v_viewer uuid;
  v_editor uuid;
  v_manager uuid;
begin
  -- 1. Viewer: Can view only their own documents
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'viewer', 'Viewer', 'Read own documents')
  returning id into v_viewer;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_viewer, id, 'own'
  from multitenancy.permissions where key = 'documents.read';

  -- 2. Editor: Can read and edit their own documents
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'editor', 'Editor', 'Create and edit own documents')
  returning id into v_editor;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_editor, id, 'own'
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update');

  -- 3. Manager: Can read, edit, and delete ALL documents in the tenant or scope
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'manager', 'Manager', 'Manage all documents and delete')
  returning id into v_manager;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_manager, id, 'all'
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update', 'documents.delete');
end $$;
```

---

### Step 3: Create Application Table & Attach RLS

Create your business table with `tenant_id`, optional `project_id` (scope), and `author_id`.

```sql
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid null,
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  content text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint fk_documents_scope foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

-- Protect tenant_id and project_id from being altered on update
create trigger trg_documents_protect
  before update on public.documents
  for each row execute function multitenancy.enforce_protected_keys_immutable('project_id');

-- Enable RLS
alter table public.documents enable row level security;
```

---

### Step 4: Write Clean RLS Policies

#### 📖 Scenario A: User reads ONLY THEIR OWN rows vs Managers read ALL rows
```sql
create policy "documents_select" on public.documents
for select to authenticated
using (
  case multitenancy.access_level(tenant_id, 'documents.read', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);
```

#### ✏️ Scenario B: User updates ONLY THEIR OWN rows vs Managers update ALL rows
```sql
create policy "documents_update" on public.documents
for update to authenticated
using (
  case multitenancy.access_level(tenant_id, 'documents.update', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
)
with check (
  case multitenancy.access_level(tenant_id, 'documents.update', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);
```

#### 🗑️ Scenario C: ONLY Managers & Owners can DELETE (access_level = 'all')
```sql
create policy "documents_delete" on public.documents
for delete to authenticated
using (
  multitenancy.has_access(tenant_id, 'documents.delete', array[project_id], 'all')
);
```

#### 🤝 Scenario D: Custom Row Predicates & Document Collaborators (Sharing)
When your application allows users to share specific documents with other tenant members via a `document_collaborators` table, compose the custom predicate inside the `own` branch:

```sql
-- 1. Create a SECURITY INVOKER helper function
create or replace function public.is_document_collaborator(
  p_document_id uuid,
  p_user_id uuid,
  p_required_level text default 'view'
)
returns boolean language sql stable security invoker as $$
  select exists (
    select 1 from public.document_collaborators
    where document_id = p_document_id
      and user_id = p_user_id
      and (p_required_level = 'view' or permission_level = 'edit')
  );
$$;

-- 2. Compose into RLS policy (Author OR Invited Collaborator)
create policy "documents_select_with_sharing" on public.documents
for select to authenticated
using (
  case multitenancy.access_level(tenant_id, 'documents.read', array[project_id])
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

## 👥 Role Assignment & Member Management

A common question is: **Can a Tenant Admin assign roles to members?**

**Yes!** Managing members and assigning roles is a core feature of the package, designed with strict enterprise security boundaries.

### 1. Responsibility Model: DBA vs Tenant Admin

| Action | Who Can Do It? | How is it done? |
| :--- | :--- | :--- |
| **Define Roles & Permissions** *(e.g. create 'Editor' role)* | **DBA Only** | SQL Migrations (`sql/templates/roles.sql`) |
| **Assign Roles to Members** *(e.g. make Alice an 'Editor')* | **Tenant Owner & Admins** | TypeScript / Python SDK & UI (`setGrants`) |
| **Invite New Members with Roles** | **Tenant Owner & Admins** | SDK (`invitations.create`) |
| **Suspend / Reactivate / Remove Members** | **Tenant Owner & Admins** | SDK (`members.suspend`, `members.remove`) |

> **Why are Roles DBA-Managed?**  
> If tenant admins could create arbitrary roles, a compromised tenant account or UI vulnerability could create a "Super-Admin" role with full database bypass. In `supabase-multitenancy`, the DBA defines the fixed role catalog, and tenant admins safely assign users to those roles.

---

### 2. How to Assign Roles

#### A. Assign Roles Upon Invitation
```ts
// Invite Alice as 'editor' in Project Alpha, and 'viewer' across the entire tenant
const invite = await mt.invitations.create(tenantId, {
  email: "alice@acme.com",
  grants: [
    { role_id: editorRoleId, scope_id: projectAlphaId }, // Project-scoped
    { role_id: viewerRoleId, scope_id: null }           // Tenant-wide
  ]
});
```

#### B. Change Roles for an Existing Member
```ts
// Update Bob's role assignments
await mt.members.setGrants(tenantId, membershipId, [
  { role_id: managerRoleId, scope_id: projectAlphaId }
]);
```

---

### 3. Delegated Admins & Anti-Escalation (`ROLE_ESCALATION` Protection)

You can delegate member management to non-owners by granting them a role with the `multitenancy.members.manage` permission.

To prevent privilege escalation attacks, the database automatically enforces **Anti-Escalation**:
> **A delegated admin CANNOT grant any role, permission, or scope that they do not personally possess.**

* **Allowed**: A Marketing Manager with `documents.write` in *Project Marketing* can assign the `editor` role to a new marketer in *Project Marketing*.
* **Blocked (`ROLE_ESCALATION: 42501`)**: If the Marketing Manager tries to grant someone access to *Project Finance* or assign a global `manager` role, the database automatically rejects the transaction.

---

## 💻 TypeScript SDK Workflow

```ts
import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-multitenancy";

// 1. Initialize Supabase and Multitenancy client
const supabase = createClient("https://xyz.supabase.co", "anon-key");
const mt = createMultitenancyClient(supabase);

// 2. Create a Tenant Organization
const { tenant_id } = await mt.createTenant({
  slug: "acme-corp",
  name: "Acme Corporation",
});

// 3. Create a Project Scope
const { scope_id: projectAlphaId } = await mt.scopes.create(tenant_id, {
  kind: "project",
  key: "alpha",
  name: "Project Alpha",
});

// 4. Invite a Member as 'editor' inside Project Alpha
const roles = await mt.roles.list(tenant_id);
const editorRole = roles.find((r) => r.key === "editor")!;

const invite = await mt.invitations.create(tenant_id, {
  email: "developer@acme.com",
  grants: [
    {
      role_id: editorRole.id,
      scope_id: projectAlphaId, // Scoped grant
    },
  ],
});

// 5. UI Authorization Check (e.g. Can render the Delete button?)
const canDelete = await mt.can(tenant_id, "documents.delete", [projectAlphaId]);
if (canDelete) {
  renderDeleteButton();
}

// 6. Query data via standard Supabase PostgREST (RLS enforced automatically!)
const { data: docs } = await supabase
  .from("documents")
  .select("*")
  .eq("tenant_id", tenant_id);
```

---

## 🐍 Python SDK Workflow

```python
from supabase import create_client
from supabase_multitenancy import MultitenancyClient

supabase = create_client("https://xyz.supabase.co", "anon-key")
mt = MultitenancyClient(supabase)

# 1. Create Tenant
tenant = mt.create_tenant(slug="acme-corp", name="Acme Corporation")
tenant_id = tenant["tenant_id"]

# 2. Check UI Permission
allowed = mt.can(tenant_id, "documents.read")
print(f"Can read documents: {allowed}")

# 3. Fetch Dashboard Context
context = mt.context(tenant_id, section="self")
print("User context:", context)
```

---

## 🎯 Architecture & Security Guarantees

| Security Feature | Implementation |
| :--- | :--- |
| **Schema Isolation** | All functions, tables, and routines live strictly in schema `multitenancy`. `public` remains completely clean. |
| **DBA-Managed Roles** | Roles and permissions can only be altered by database migrations. Tenant admins cannot elevate roles (`ROLE_ESCALATION` guard). |
| **Append-Only Audit Log** | Audit table triggers prohibit `UPDATE` and `DELETE` even for administrators (`TRUNCATE` revoked). |
| **One-Time Token Hashing** | Invitations store only SHA-256 hashes of cryptographically random 256-bit entropy tokens. |
| **Key Immutability** | Foreign keys (`tenant_id`, `scope_id`) are immutable after insertion via `enforce_protected_keys_immutable()`. |

---

## 📚 Examples Directory
 
Explore fully runnable examples in [`examples/`](file:///Users/alexander/dev/supabase-tenant-rbac/examples):
- [`examples/1-saas-starter-documents`](file:///Users/alexander/dev/supabase-tenant-rbac/examples/1-saas-starter-documents): Multi-tenant documents app with `viewer`, `editor`, and `manager` roles.
- [`examples/2-collaborators-and-custom-predicates`](file:///Users/alexander/dev/supabase-tenant-rbac/examples/2-collaborators-and-custom-predicates): Document sharing & collaborators list via custom `SECURITY INVOKER` predicates.

---

## 📄 License

MIT © [Alexander Cherkasov](https://github.com/AlexanderCherkasov) & contributors.
