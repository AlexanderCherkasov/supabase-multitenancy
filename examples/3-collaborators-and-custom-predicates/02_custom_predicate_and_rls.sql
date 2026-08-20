-- Step 2: Custom Predicate Function and Row-Level Security Policies

-- ----------------------------------------------------------------------------
-- Custom Predicate Helper Function (SECURITY INVOKER)
-- Checks whether a user is an explicitly assigned collaborator on a document.
-- ----------------------------------------------------------------------------
create or replace function public.is_document_collaborator(
  p_document_id uuid,
  p_user_id uuid,
  p_required_level text default 'view'
)
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select exists (
    select 1
    from public.document_collaborators dc
    where dc.document_id = p_document_id
      and dc.user_id = p_user_id
      and (
        p_required_level = 'view'
        or dc.permission_level = 'edit'
      )
  );
$$;

-- Grant execution to authenticated users
grant execute on function public.is_document_collaborator(uuid, uuid, text) to authenticated;

-- ----------------------------------------------------------------------------
-- RLS Policies on `public.documents`
-- ----------------------------------------------------------------------------

-- 1. SELECT (Read Documents)
-- - 'all'  -> Can read all documents in tenant/scope (e.g. Managers, Owners).
-- - 'own'  -> Can read if they are the AUTHOR OR an explicitly invited COLLABORATOR.
-- - 'none' -> Denied.
drop policy if exists "documents_select_collab" on public.documents;
create policy "documents_select_collab"
on public.documents
for select
to authenticated
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

-- 2. UPDATE (Edit Documents)
-- - 'all'  -> Can edit all documents in tenant/scope.
-- - 'own'  -> Can edit if they are the AUTHOR OR an invited COLLABORATOR with 'edit' level.
-- - 'none' -> Denied.
drop policy if exists "documents_update_collab" on public.documents;
create policy "documents_update_collab"
on public.documents
for update
to authenticated
using (
  case api.access_level(tenant_id, 'documents.update', array[project_id])
    when 'all' then true
    when 'own' then (
      author_id = auth.uid()
      or public.is_document_collaborator(id, auth.uid(), 'edit')
    )
    else false
  end
)
with check (
  case api.access_level(tenant_id, 'documents.update', array[project_id])
    when 'all' then true
    when 'own' then (
      author_id = auth.uid()
      or public.is_document_collaborator(id, auth.uid(), 'edit')
    )
    else false
  end
);

-- 3. INSERT (Create Documents)
drop policy if exists "documents_insert_collab" on public.documents;
create policy "documents_insert_collab"
on public.documents
for insert
to authenticated
with check (
  author_id = auth.uid()
  and api.has_access(tenant_id, 'documents.create', array[project_id], 'own')
);

-- 4. DELETE (Remove Documents)
-- - Managers with 'all' level OR original author.
drop policy if exists "documents_delete_collab" on public.documents;
create policy "documents_delete_collab"
on public.documents
for delete
to authenticated
using (
  api.has_access(tenant_id, 'documents.delete', array[project_id], 'all')
  or (
    author_id = auth.uid()
    and api.has_access(tenant_id, 'documents.delete', array[project_id], 'own')
  )
);

-- ----------------------------------------------------------------------------
-- RLS Policies on `public.document_collaborators`
-- Authors of a document or tenant managers can manage the collaborators list.
-- ----------------------------------------------------------------------------
drop policy if exists "collaborators_select" on public.document_collaborators;
create policy "collaborators_select"
on public.document_collaborators
for select
to authenticated
using (
  user_id = auth.uid()
  or api.has_access(tenant_id, 'documents.read', null, 'all')
  or exists (
    select 1 from public.documents d
    where d.id = document_collaborators.document_id and d.author_id = auth.uid()
  )
);

drop policy if exists "collaborators_manage" on public.document_collaborators;
create policy "collaborators_manage"
on public.document_collaborators
for all
to authenticated
using (
  api.has_access(tenant_id, 'documents.update', null, 'all')
  or exists (
    select 1 from public.documents d
    where d.id = document_collaborators.document_id and d.author_id = auth.uid()
  )
)
with check (
  api.has_access(tenant_id, 'documents.update', null, 'all')
  or exists (
    select 1 from public.documents d
    where d.id = document_collaborators.document_id and d.author_id = auth.uid()
  )
);
