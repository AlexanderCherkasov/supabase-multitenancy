-- Step 3: Application Business Table & Row-Level Security (RLS)
-- This table is owned by the consumer application.

create table if not exists public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid null,
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  content text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- Foreign key enforces that project_id belongs to the same tenant
  constraint fk_documents_scope foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

-- Fast lookup indexes
create index if not exists idx_documents_tenant_project on public.documents(tenant_id, project_id);
create index if not exists idx_documents_author on public.documents(author_id);

-- Enforce that tenant_id and project_id cannot be modified once inserted
drop trigger if exists trg_documents_protected_keys on public.documents;
create trigger trg_documents_protected_keys
  before update on public.documents
  for each row execute function api.enforce_protected_keys_immutable('project_id');

-- Enable RLS
alter table public.documents enable row level security;

-- ----------------------------------------------------------------------------
-- RLS Policy 1: SELECT (Read Documents)
-- - Tenant owners & users with 'all' access can read ALL documents in the tenant/scope.
-- - Users with 'own' access can read ONLY their own documents (author_id = auth.uid()).
-- - Outsiders receive access_level = 'none' and see 0 rows.
-- ----------------------------------------------------------------------------
drop policy if exists "documents_select_policy" on public.documents;
create policy "documents_select_policy"
on public.documents
for select
to authenticated
using (
  case api.access_level(tenant_id, 'documents.read', array[project_id])
    when 'all' then true
    when 'own' then author_id = auth.uid()
    else false
  end
);

-- ----------------------------------------------------------------------------
-- RLS Policy 2: INSERT (Create Documents)
-- - Must have 'documents.create' permission in tenant/scope.
-- - Must set author_id to auth.uid() (cannot forge authorship).
-- ----------------------------------------------------------------------------
drop policy if exists "documents_insert_policy" on public.documents;
create policy "documents_insert_policy"
on public.documents
for insert
to authenticated
with check (
  author_id = auth.uid()
  and api.has_access(tenant_id, 'documents.create', array[project_id], 'own')
);

-- ----------------------------------------------------------------------------
-- RLS Policy 3: UPDATE (Edit Documents)
-- - Users with 'all' access (e.g. Managers, Owners) can edit ANY document.
-- - Users with 'own' access (e.g. Editors) can edit ONLY documents where author_id = auth.uid().
-- ----------------------------------------------------------------------------
drop policy if exists "documents_update_policy" on public.documents;
create policy "documents_update_policy"
on public.documents
for update
to authenticated
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

-- ----------------------------------------------------------------------------
-- RLS Policy 4: DELETE (Remove Documents)
-- - Only users with 'all' access level (e.g. Managers, Tenant Owners) can delete documents.
-- ----------------------------------------------------------------------------
drop policy if exists "documents_delete_policy" on public.documents;
create policy "documents_delete_policy"
on public.documents
for delete
to authenticated
using (
  api.has_access(tenant_id, 'documents.delete', array[project_id], 'all')
);
