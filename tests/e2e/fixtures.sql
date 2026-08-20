-- Disposable local-stack application fixture. Apply after sql/install.sql.
-- Role definitions are DBA-owned migration data; browser tests only consume
-- them through authenticated api RPCs.

insert into multitenancy.permissions (key, origin, description) values
  ('documents.read', 'application', 'Read documents'),
  ('documents.create', 'application', 'Create documents'),
  ('documents.update', 'application', 'Update documents'),
  ('documents.delete', 'application', 'Delete documents')
on conflict (key) do update
set description = excluded.description,
    is_deprecated = false;

insert into multitenancy.roles (key, name, description) values
  ('e2e_writer', 'E2E writer', 'Own CRUD inside an assigned project'),
  ('e2e_limited_admin', 'E2E limited admin', 'May manage members but cannot grant document-all'),
  ('e2e_manager', 'E2E manager', 'Document-wide access used to prove escalation denial')
on conflict (key) do update
set name = excluded.name,
    description = excluded.description;

insert into multitenancy.role_permissions (role_id, permission_id, access_level)
select r.id, p.id, x.access_level
from (
  values
    ('e2e_writer', 'documents.read', 'own'),
    ('e2e_writer', 'documents.create', 'own'),
    ('e2e_writer', 'documents.update', 'own'),
    ('e2e_limited_admin', 'multitenancy.members.manage', 'all'),
    ('e2e_limited_admin', 'documents.read', 'own'),
    ('e2e_manager', 'documents.read', 'all'),
    ('e2e_manager', 'documents.create', 'all'),
    ('e2e_manager', 'documents.update', 'all'),
    ('e2e_manager', 'documents.delete', 'all')
) as x(role_key, permission_key, access_level)
join multitenancy.roles r on r.key = x.role_key
join multitenancy.permissions p on p.key = x.permission_key
on conflict (role_id, permission_id) do update
set access_level = excluded.access_level;

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
  for each row execute function api.enforce_protected_keys_immutable('tenant_id', 'project_id');

drop policy if exists "documents select" on public.documents;
create policy "documents select" on public.documents for select to authenticated
using (
  (select api.has_access(tenant_id, 'documents.read', array[project_id], 'all'))
  or (
    (select api.has_access(tenant_id, 'documents.read', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents insert" on public.documents;
create policy "documents insert" on public.documents for insert to authenticated
with check (
  (select api.has_access(tenant_id, 'documents.create', array[project_id], 'all'))
  or (
    (select api.has_access(tenant_id, 'documents.create', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents update" on public.documents;
create policy "documents update" on public.documents for update to authenticated
using (
  (select api.has_access(tenant_id, 'documents.update', array[project_id], 'all'))
  or (
    (select api.has_access(tenant_id, 'documents.update', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
)
with check (
  (select api.has_access(tenant_id, 'documents.update', array[project_id], 'all'))
  or (
    (select api.has_access(tenant_id, 'documents.update', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

drop policy if exists "documents delete" on public.documents;
create policy "documents delete" on public.documents for delete to authenticated
using (
  (select api.has_access(tenant_id, 'documents.delete', array[project_id], 'all'))
  or (
    (select api.has_access(tenant_id, 'documents.delete', array[project_id], 'own'))
    and author_id = (select auth.uid())
  )
);

grant select, insert, update, delete on public.documents to authenticated;
