-- 007_rpc_tenant.sql
-- supabase-multitenancy v0.3.0 — Tenant lifecycle & permission check RPCs
-- Purpose: Self-service tenant onboarding and UI permission helper.
-- Dependencies: 006_authorize

-- ============================================================================
-- 1. TENANT CREATION
-- ============================================================================

create or replace function multitenancy.create_tenant(
  p_slug text,
  p_name text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid       uuid := auth.uid();
  v_tenant_id uuid;
  v_slug      text := lower(p_slug);
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  if not coalesce((select self_service_tenant_creation from multitenancy.settings where id = 1), false) then
    raise exception 'FORBIDDEN: self-service tenant creation is disabled' using errcode = '42501';
  end if;

  if v_slug !~ '^[a-z0-9-]{3,40}$' then
    raise exception 'INVALID_INPUT: slug must match ^[a-z0-9-]{3,40}$' using errcode = '22P02';
  end if;

  if char_length(p_name) not between 2 and 120 then
    raise exception 'INVALID_INPUT: name length 2..120' using errcode = '22P02';
  end if;

  insert into multitenancy.tenants (slug, name, owner_user_id)
  values (v_slug, p_name, v_uid)
  returning id into v_tenant_id;

  insert into multitenancy.profiles (user_id)
  values (v_uid)
  on conflict (user_id) do nothing;

  insert into multitenancy.memberships (tenant_id, user_id, status)
  values (v_tenant_id, v_uid, 'active')
  on conflict (tenant_id, user_id)
  do update set status = 'active', updated_at = now();

  insert into multitenancy.audit_events (
    tenant_id, actor_user_id, command, entity_type, entity_id, payload
  )
  values (
    v_tenant_id, v_uid, 'tenant.create', 'tenant', v_tenant_id::text,
    jsonb_build_object('slug', v_slug, 'name', p_name)
  );

  return jsonb_build_object(
    'api_version', 1,
    'data', jsonb_build_object(
      'tenant_id', v_tenant_id,
      'slug',      v_slug,
      'name',      p_name
    )
  );
exception
  when unique_violation then
    raise exception 'CONFLICT: slug already exists' using errcode = '23505';
end;
$$;

revoke all on function multitenancy.create_tenant(text, text) from public, anon;
grant execute on function multitenancy.create_tenant(text, text) to authenticated, service_role;


-- ============================================================================
-- 2. PERMISSION CHECK (UI HELPER)
-- ============================================================================

create or replace function multitenancy.can(
  p_tenant_id   uuid,
  p_permission  text,
  p_scope_ids   uuid[]
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_allowed boolean;
begin
  if auth.uid() is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  v_allowed := multitenancy.authorize(p_tenant_id, p_permission, p_scope_ids);

  return jsonb_build_object(
    'api_version', 1,
    'data',        jsonb_build_object('allowed', v_allowed)
  );
end;
$$;

revoke all on function multitenancy.can(uuid, text, uuid[]) from public, anon;
grant execute on function multitenancy.can(uuid, text, uuid[]) to authenticated, service_role;
