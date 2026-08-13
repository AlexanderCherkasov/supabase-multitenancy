-- Reviewed RLS template for a scoped, ownable application table.
-- Copy into a consumer migration and replace `documents`, `project_id`,
-- `author_id`, and permission keys as needed.

alter table public.documents enable row level security;

create index if not exists documents_tenant_scope_idx
  on public.documents(tenant_id, project_id);

do $$ begin
  if not exists (
    select 1 from pg_catalog.pg_constraint
    where conname = 'documents_tenant_project_fk'
      and conrelid = 'public.documents'::regclass
  ) then
    alter table public.documents
      add constraint documents_tenant_project_fk
      foreign key (tenant_id, project_id)
      references multitenancy.scopes(tenant_id, id)
      on delete restrict;
  end if;
end $$;

drop trigger if exists multitenancy_protected_keys_immutable on public.documents;
create trigger multitenancy_protected_keys_immutable
  before update on public.documents
  for each row execute function multitenancy.enforce_protected_keys_immutable('tenant_id', 'project_id');

drop policy if exists "documents select" on public.documents;
create policy "documents select" on public.documents
  for select to authenticated
  using (
    (select multitenancy.has_access(tenant_id, 'documents.read', array[project_id], 'all'))
    or (
      (select multitenancy.has_access(tenant_id, 'documents.read', array[project_id], 'own'))
      and author_id = (select auth.uid())
    )
  );

drop policy if exists "documents insert" on public.documents;
create policy "documents insert" on public.documents
  for insert to authenticated
  with check (
    (select multitenancy.has_access(tenant_id, 'documents.create', array[project_id], 'all'))
    or (
      (select multitenancy.has_access(tenant_id, 'documents.create', array[project_id], 'own'))
      and author_id = (select auth.uid())
    )
  );

drop policy if exists "documents update" on public.documents;
create policy "documents update" on public.documents
  for update to authenticated
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
create policy "documents delete" on public.documents
  for delete to authenticated
  using (
    (select multitenancy.has_access(tenant_id, 'documents.delete', array[project_id], 'all'))
    or (
      (select multitenancy.has_access(tenant_id, 'documents.delete', array[project_id], 'own'))
      and author_id = (select auth.uid())
    )
  );

-- Data API privileges are separate from RLS. Grant only after reviewing the
-- policies and your project's Data API exposure settings.
grant select, insert, update, delete on public.documents to authenticated;
