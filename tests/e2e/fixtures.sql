-- Illustrative disposable-project fixture. Apply after sql/install.sql.

insert into multitenancy.permissions (key, origin, description) values
  ('documents.read', 'application', 'Read documents'),
  ('documents.create', 'application', 'Create documents'),
  ('documents.update', 'application', 'Update documents'),
  ('documents.delete', 'application', 'Delete documents')
on conflict (key) do update
set description = excluded.description,
    is_deprecated = false;

create table if not exists public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid not null,
  author_id uuid not null references auth.users(id),
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now(),
  foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

create index if not exists documents_tenant_project_idx
  on public.documents(tenant_id, project_id);

alter table public.documents enable row level security;

drop trigger if exists multitenancy_protected_keys_immutable on public.documents;
create trigger multitenancy_protected_keys_immutable
  before update on public.documents
  for each row execute function multitenancy.enforce_protected_keys_immutable('tenant_id', 'project_id');

drop policy if exists "documents select" on public.documents;
create policy "documents select" on public.documents for select to authenticated
using (
  (select multitenancy.has_access(tenant_id, 'documents.read', array[project_id], 'all'))
  or (
    (select multitenancy.has_access(tenant_id, 'documents.read', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents insert" on public.documents;
create policy "documents insert" on public.documents for insert to authenticated
with check (
  (select multitenancy.has_access(tenant_id, 'documents.create', array[project_id], 'all'))
  or (
    (select multitenancy.has_access(tenant_id, 'documents.create', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents update" on public.documents;
create policy "documents update" on public.documents for update to authenticated
using (
  (select multitenancy.has_access(tenant_id, 'documents.update', array[project_id], 'all'))
  or (
    (select multitenancy.has_access(tenant_id, 'documents.update', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
)
with check (
  (select multitenancy.has_access(tenant_id, 'documents.update', array[project_id], 'all'))
  or (
    (select multitenancy.has_access(tenant_id, 'documents.update', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents delete" on public.documents;
create policy "documents delete" on public.documents for delete to authenticated
using (
  (select multitenancy.has_access(tenant_id, 'documents.delete', array[project_id], 'all'))
  or (
    (select multitenancy.has_access(tenant_id, 'documents.delete', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

grant select, insert, update, delete on public.documents to authenticated;
