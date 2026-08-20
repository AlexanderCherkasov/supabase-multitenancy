-- 015_admin_router.sql
-- supabase-multitenancy v0.3.0 — Central administrative dispatcher & grant validation
-- Purpose: Unified admin router with strict pre-validation and role mutation restrictions.
-- Dependencies: 006_authorize, 011_admin_tenant, 012_admin_scope, 013_admin_member, 014_admin_invitation

drop function if exists public.multitenancy_admin(uuid, text, jsonb);

-- ============================================================================
-- 1. INPUT VALIDATION: GRANTS
-- ============================================================================

-- Validate grant references before mutations replace existing assignments.
create or replace function multitenancy.validate_grants(
  p_tenant_id uuid,
  p_grants    jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  g                 jsonb;
  v_role_id         uuid;
  v_role_key        text;
  v_role_tenant_id  uuid;
  v_scope_tenant_id uuid;
begin
  if jsonb_typeof(coalesce(p_grants, '[]'::jsonb)) <> 'array' then
    raise exception 'INVALID_INPUT: grants must be an array' using errcode = '22P02';
  end if;

  for g in select value from jsonb_array_elements(coalesce(p_grants, '[]'::jsonb)) loop
    -- Require exactly one of role_id or role_key
    if (nullif(g->>'role_id', '') is null) = (nullif(g->>'role_key', '') is null) then
      raise exception 'INVALID_INPUT: exactly one of role_id or role_key is required' using errcode = '22P02';
    end if;

    if nullif(g->>'role_id', '') is not null then
      begin
        v_role_id := (g->>'role_id')::uuid;
      exception when invalid_text_representation then
        raise exception 'INVALID_INPUT: role_id must be a UUID' using errcode = '22P02';
      end;
      select tenant_id into v_role_tenant_id
      from multitenancy.roles
      where id = v_role_id;
    else
      v_role_key := nullif(g->>'role_key', '');
      select tenant_id into v_role_tenant_id
      from multitenancy.roles
      where key = v_role_key;
    end if;

    if not found then
      raise exception 'INVALID_INPUT: role does not exist' using errcode = '22P02';
    end if;

    if v_role_tenant_id is not null and v_role_tenant_id <> p_tenant_id then
      raise exception 'INVALID_INPUT: role is restricted to another tenant' using errcode = '22P02';
    end if;

    if nullif(g->>'scope_id', '') is not null then
      begin
        select tenant_id into v_scope_tenant_id
        from multitenancy.scopes
        where id = (g->>'scope_id')::uuid;
      exception when invalid_text_representation then
        raise exception 'INVALID_INPUT: scope_id must be a UUID' using errcode = '22P02';
      end;

      if v_scope_tenant_id is null or v_scope_tenant_id <> p_tenant_id then
        raise exception 'INVALID_INPUT: scope belongs to another tenant' using errcode = '22P02';
      end if;
    end if;
  end loop;
end;
$$;

revoke all on function multitenancy.validate_grants(uuid, jsonb) from public, anon;
grant execute on function multitenancy.validate_grants(uuid, jsonb) to authenticated, service_role;


-- ============================================================================
-- 2. CENTRAL ADMIN ROUTER
-- ============================================================================

create or replace function multitenancy.admin(
  p_tenant_id uuid,
  p_command   text,
  p_payload   jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid      uuid := auth.uid();
  v_is_owner boolean;
  v_data     jsonb;
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  select (owner_user_id = v_uid) into v_is_owner
  from multitenancy.tenants
  where id = p_tenant_id;

  if v_is_owner is null then
    raise exception 'NOT_FOUND' using errcode = '42704';
  end if;

  if not exists (
    select 1
    from multitenancy.memberships
    where tenant_id = p_tenant_id
      and user_id   = v_uid
      and status    = 'active'
  ) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  if p_command like 'role.%' then
    raise exception 'FORBIDDEN: roles and role permissions are DBA-managed' using errcode = '42501';
  end if;

  if p_command in ('member.set_grants', 'invitation.create') then
    perform multitenancy.validate_grants(p_tenant_id, p_payload->'grants');
  end if;

  case split_part(p_command, '.', 1)
    when 'tenant' then
      v_data := multitenancy._admin_tenant(
        v_uid, p_tenant_id, v_is_owner, p_command, p_payload
      );

    when 'scope' then
      v_data := multitenancy._admin_scope(
        v_uid, p_tenant_id, v_is_owner, p_command, p_payload
      );

    when 'member' then
      v_data := multitenancy._admin_member(
        v_uid, p_tenant_id, v_is_owner, p_command, p_payload
      );

    when 'invitation' then
      v_data := multitenancy._admin_invitation(
        v_uid, p_tenant_id, v_is_owner, p_command, p_payload
      );

    else
      raise exception 'INVALID_INPUT: unknown command %', p_command using errcode = '22P02';
  end case;

  return jsonb_build_object(
    'api_version', 1,
    'data',        v_data
  );
end;
$$;

revoke all on function multitenancy.admin(uuid, text, jsonb) from public, anon;
grant execute on function multitenancy.admin(uuid, text, jsonb) to authenticated, service_role;
