-- ============================================================================
-- 02_tasks_table_and_rls.sql: Scoped Tasks Table & Strict Scope RLS Policies
-- ============================================================================

-- 1. Create Business Table
create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid not null, -- Scope reference
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'done')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- 🔒 COMPOSITE FOREIGN KEY: Guarantees that project_id belongs strictly to tenant_id
  constraint fk_tasks_tenant_project foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

-- Fast lookup composite indexes
create index if not exists idx_tasks_tenant_project on public.tasks(tenant_id, project_id);
create index if not exists idx_tasks_tenant_author on public.tasks(tenant_id, author_id);

-- Enforce key immutability (tasks cannot be moved to another tenant or project on update)
drop trigger if exists trg_tasks_protect on public.tasks;
create trigger trg_tasks_protect
  before update on public.tasks
  for each row execute function api.enforce_protected_keys_immutable('tenant_id', 'project_id');

-- Enable Row-Level Security
alter table public.tasks enable row level security;

-- ----------------------------------------------------------------------------
-- RLS Policy 1: SELECT (Read Tasks in Scope)
-- - Users with 'all' in the project (or tenant-wide) can view ALL tasks in the project.
-- - Users with 'own' in the project can view ONLY tasks they created (author_id = auth.uid()).
-- - Users with no grant in this project receive 'none' and see 0 rows.
-- ----------------------------------------------------------------------------
drop policy if exists "tasks_select_policy" on public.tasks;
create policy "tasks_select_policy"
on public.tasks
for select
to authenticated
using (
  case api.access_level(tenant_id, 'tasks.read', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);

-- ----------------------------------------------------------------------------
-- RLS Policy 2: INSERT (Create Task in Scope)
-- - Must hold 'tasks.create' in that specific project_id (or tenant-wide).
-- - Must set author_id to auth.uid().
-- ----------------------------------------------------------------------------
drop policy if exists "tasks_insert_policy" on public.tasks;
create policy "tasks_insert_policy"
on public.tasks
for insert
to authenticated
with check (
  author_id = auth.uid()
  and api.has_access(tenant_id, 'tasks.create', array[project_id], 'own')
);

-- ----------------------------------------------------------------------------
-- RLS Policy 3: UPDATE (Edit Tasks in Scope)
-- - 'all' access in the project: can edit ANY task in that project.
-- - 'own' access in the project: can edit ONLY their own tasks in that project.
-- ----------------------------------------------------------------------------
drop policy if exists "tasks_update_policy" on public.tasks;
create policy "tasks_update_policy"
on public.tasks
for update
to authenticated
using (
  case api.access_level(tenant_id, 'tasks.update', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
)
with check (
  case api.access_level(tenant_id, 'tasks.update', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);

-- ----------------------------------------------------------------------------
-- RLS Policy 4: DELETE (Delete Tasks in Scope)
-- - Only users with 'all' level in that project (or tenant owners) can delete tasks.
-- ----------------------------------------------------------------------------
drop policy if exists "tasks_delete_policy" on public.tasks;
create policy "tasks_delete_policy"
on public.tasks
for delete
to authenticated
using (
  api.has_access(tenant_id, 'tasks.delete', array[project_id], 'all')
);
