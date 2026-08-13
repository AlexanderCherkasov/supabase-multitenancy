-- Application-owned custom row predicate.
-- It is called directly by a generated RLS policy, never through SECURITY DEFINER.
create schema if not exists app;

create or replace function app.can_collaborate_on_document(
  p_user_id uuid,
  p_tenant_id uuid,
  p_row jsonb
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
    where dc.tenant_id = p_tenant_id
      and dc.document_id = (p_row ->> 'id')::uuid
      and dc.user_id = p_user_id
  )
$$;

revoke all on function app.can_collaborate_on_document(uuid, uuid, jsonb) from public, anon;
grant usage on schema app to authenticated;
grant execute on function app.can_collaborate_on_document(uuid, uuid, jsonb) to authenticated;

-- Add a direct call to this function in the `own` branch of the consumer RLS
-- migration. Do not route it through a package SECURITY DEFINER function.
