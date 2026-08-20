# supabase-multitenancy

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![AI Agent Guide](https://img.shields.io/badge/AI%20Agent-Design%20Guide-purple.svg)](AGENT_GUIDE.md)

A SQL-first multi-tenancy and RBAC foundation for **Supabase**. The database is the source of truth: tenant namespaces, typed scopes, memberships, DBA-managed global and tenant-specific role profiles, `own|all` RLS authorization, invitations, audit logging, and paginated RPCs.

> 🤖 **Building with AI Agents?** See [`AGENT_GUIDE.md`](AGENT_GUIDE.md) for deterministic prompt rules, schema patterns, and canonical RLS templates for LLM assistants (Antigravity, Cursor, Claude Code, Copilot).

- **Private package schema**: Tables and implementation live in private `multitenancy`; browser RPCs and RLS helpers are exposed through the thin `api` schema.
- **SQL-First & Safe**: Roles and permissions are DBA-managed migration data. Tenant admins cannot elevate privileges.
- **`own` vs `all` Access Contract**: Express fine-grained authorization (read own rows vs read all tenant rows) with single-line SQL predicates.
- **Full SDK Support**: Typed TypeScript and Python SDKs for user-session operations and UI permission checks (`can()`).

---

## 📦 Quick Installation

### 1. Database Package (SQL Migration)

Create a new Supabase migration and paste the contents of [`sql/install.sql`](sql/install.sql):

```bash
supabase migration new install_multitenancy
# Copy sql/install.sql into supabase/migrations/<timestamp>_install_multitenancy.sql
supabase db push
```

### 2. Client SDKs

Install directly from GitHub or vendor into your project:

```bash
# TypeScript / JavaScript (via GitHub)
npm install github:AlexanderCherkasov/supabase-multitenancy @supabase/supabase-js

# Python (via GitHub)
pip install "git+https://github.com/AlexanderCherkasov/supabase-multitenancy.git#subdirectory=python"
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
  -- Omitting tenant_id makes a global role available in every tenant.
  insert into multitenancy.roles (key, name, description)
  values ('viewer', 'Viewer', 'Read own documents')
  returning id into v_viewer;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_viewer, id, 'own'
  from multitenancy.permissions where key = 'documents.read';

  -- 2. Editor: Can read and edit their own documents
  insert into multitenancy.roles (key, name, description)
  values ('editor', 'Editor', 'Create and edit own documents')
  returning id into v_editor;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_editor, id, 'own'
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update');

  -- 3. Manager: Can read, edit, and delete ALL documents in the tenant or scope
  insert into multitenancy.roles (key, name, description)
  values ('manager', 'Manager', 'Manage all documents and delete')
  returning id into v_manager;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_manager, id, 'all'
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update', 'documents.delete');
end $$;
```

`tenant_id` is deliberately omitted above: these are global roles. A rare
tenant-specific role is also DBA migration data, never a tenant-admin action:
set its `tenant_id` and give it a distinct application-wide key, for example
`acme_compliance_reviewer`. It is assignable only in that tenant and appears
alongside global roles in `roles.list(tenantId)`.

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

-- Protect BOTH tenant_id and project_id from being altered on update
create trigger trg_documents_protect
  before update on public.documents
  for each row execute function api.enforce_protected_keys_immutable('tenant_id', 'project_id');

-- Enable RLS
alter table public.documents enable row level security;
```

---

### Step 4: Write Clean RLS Policies

> 💡 **Nullable Scopes (`project_id NULL`)**:  
> If your table allows unscoped tenant-wide rows (`project_id is null`), simply pass `array[project_id]`. `api.access_level()` automatically normalizes `{NULL}` to an unscoped request, ensuring tenant-wide managers and members access unscoped rows while project-scoped users access only their assigned scopes.

#### 📖 Scenario A: User reads ONLY THEIR OWN rows vs Managers read ALL rows
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

#### ✏️ Scenario B: User updates ONLY THEIR OWN rows vs Managers update ALL rows
```sql
create policy "documents_update" on public.documents
for update to authenticated
using (
  case api.access_level(tenant_id, 'documents.update', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
)
with check (
  case api.access_level(tenant_id, 'documents.update', array[project_id])
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
  api.has_access(tenant_id, 'documents.delete', array[project_id], 'all')
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

## ⚡ Performance & RLS Benchmarks

All authorization checks in `supabase-multitenancy` are designed for low latency on standard PostgreSQL. Security functions run as `SECURITY DEFINER` with fixed `search_path = ''`. Because RLS predicates evaluate per candidate row returned by an index filter, authorization lookup speed is critical.

### 1. Direct Authorization Latency (`api.access_level`)

Micro-benchmarking 200 sample iterations per role tier on local PostgreSQL 15:

| User Tier | Access Level | p50 (Median) | p95 | Mean Latency | Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tenant Owner** | `is_owner` bypass exit | **`0.010 ms`** | `0.012 ms` | `0.010 ms` | ~100,000 checks/sec |
| **Outsider** | Non-member fast exit | **`0.009 ms`** | `0.011 ms` | `0.010 ms` | ~103,000 checks/sec |
| **Manager** | Tenant-wide `all` check | **`0.014 ms`** | `0.018 ms` | `0.014 ms` | ~70,000 checks/sec |
| **Writer** | Scoped `own` check | **`0.018 ms`** | `0.024 ms` | `0.019 ms` | ~53,000 checks/sec |

### 2. End-to-End Query Latency on 100,000 Rows

Comparison on a table with 100,000 rows indexed on `(tenant_id, project_id)`:

| Query Scenario | p50 (ms) | p95 (ms) | Mean (ms) | QPS |
| :--- | :--- | :--- | :--- | :--- |
| **Single Row PK Lookup (No RLS)** | `0.010 ms` | `0.012 ms` | `0.011 ms` | ~92,000 QPS |
| **Single Row PK Lookup (Manager 'all')** | `0.045 ms` | `0.053 ms` | `0.045 ms` | ~22,000 QPS |
| **Single Row PK Lookup (Writer 'own')** | `0.042 ms` | `0.067 ms` | `0.047 ms` | ~21,000 QPS |
| **Single Row PK Lookup (Outsider Denied)** | `0.029 ms` | `0.037 ms` | `0.030 ms` | ~33,000 QPS |
| **50-Row Filter Scan (Baseline, Direct filter)** | `0.013 ms` | `0.015 ms` | `0.014 ms` | ~74,000 QPS |
| **50-Row Filter Scan (Supabase-MT Manager)** | `0.776 ms` | `0.884 ms` | `0.793 ms` | ~1,260 QPS |

### 3. How to Reproduce Benchmarks Locally

Run the automated benchmark suite against your local PostgreSQL instance:

```bash
npm run benchmark
```

> **Why is evaluation fast ($10\text{–}19\ \mu\text{s}$ per row)?**
> 1. **Index-Covered Queries**: Role assignments and memberships are indexed with unique composite B-trees (`tenant_id`, `membership_id`, `scope_id`).
> 2. **Short-Circuit Exits**: Owners and non-members exit immediately on the first index probe.
> 3. **Buffer Pool Caching**: The compact RBAC catalog stays resident in PostgreSQL shared memory buffers.

---

## 🎯 Architecture & Security Guarantees

| Security Feature | Implementation |
| :--- | :--- |
| **Schema Isolation** | Private tables and implementation live in `multitenancy`; exposed client wrappers live in `api`; `public` remains application-owned. |
| **DBA-Managed Roles** | Roles and permissions can only be altered by database migrations. Tenant admins cannot elevate roles (`ROLE_ESCALATION` guard). |
| **Append-Only Audit Log** | Audit table triggers prohibit `UPDATE` and `DELETE` even for administrators (`TRUNCATE` revoked). |
| **One-Time Token Hashing** | Invitations store only SHA-256 hashes of cryptographically random 256-bit entropy tokens. |
| **Key Immutability** | Foreign keys (`tenant_id`, `scope_id`) are immutable after insertion via `enforce_protected_keys_immutable()`. |

## 📚 Examples Directory

Explore fully runnable examples in [`examples/`](examples):
- [`examples/1-saas-starter-documents`](examples/1-saas-starter-documents): Multi-tenant documents app with global `viewer`, `editor`, and `manager` roles.
- [`examples/2-project-scoped-tasks`](examples/2-project-scoped-tasks): Strict project scope restrictions and multi-project isolation within an organization.
- [`examples/3-collaborators-and-custom-predicates`](examples/3-collaborators-and-custom-predicates): Document sharing & collaborators list via custom `SECURITY INVOKER` predicates.

---

## 🤖 AI Agent Skills & Agentic Development

This repository includes first-class support for **AI Coding Assistants** (Antigravity, Cursor, Claude Code, GitHub Copilot, Codex).

### Included Agent Assets

| Resource | Purpose | Path |
| :--- | :--- | :--- |
| **Agent Skill** | Pre-configured skill definition with triggers, guardrails, and templates | [`.skills/supabase-multitenancy/SKILL.md`](.skills/supabase-multitenancy/SKILL.md) |
| **Agent Skill (Mirror)** | Standard `.agents` mirror for agent compatibility | [`.agents/skills/supabase-multitenancy/SKILL.md`](.agents/skills/supabase-multitenancy/SKILL.md) |
| **Implementation Guide** | Full design document with canonical RLS patterns and anti-pattern checklists | [`AGENT_GUIDE.md`](AGENT_GUIDE.md) |
| **LLM Discovery** | Standard LLM summary file for fast context ingestion | [`llms.txt`](llms.txt) |
| **Agent Rules** | Workspace-level rules for AI coding assistants | [`AGENTS.md`](AGENTS.md) |

### How to Use with AI Agents

When building features with an AI assistant in a project that uses `supabase-multitenancy`, prompt your agent:

```markdown
You are building a multi-tenant feature on Supabase.
Follow the guidelines and RLS patterns in `.skills/supabase-multitenancy/SKILL.md` and `AGENT_GUIDE.md`:
1. Use exposed `api` wrappers for client RPCs/RLS; keep package tables and implementation private in `multitenancy`.
2. Define permissions and roles with `'own'` vs `'all'` access levels.
3. Protect business tables with `api.enforce_protected_keys_immutable()`.
4. Generate RLS policies using `api.access_level()` and `api.has_access()`.
```

---

## 📄 License

MIT © [Alexander Cherkasov](https://github.com/AlexanderCherkasov) & contributors.
