-- 011_admin_tenant.sql
-- supabase-multitenancy v0.3.0 — Tenant administration routines & audit helper
-- Purpose: Private handlers for tenant metadata updates, lifecycle, and ownership transfer.
-- Dependencies: 005_audit, 006_authorize

-- ============================================================================
-- 1. INTERNAL AUDIT LOGGER HELPER
-- ============================================================================

create or replace function multitenancy._admin_audit(
  p_tenant_id   uuid,
  p_actor_id    uuid,
  p_command     text,
  p_entity_type text,
  p_entity_id   text,
  p_payload     jsonb default '{}'::jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into multitenancy.audit_events (
    tenant_id,
    actor_user_id,
    command,
    entity_type,
    entity_id,
    payload
  ) values (
    p_tenant_id,
    p_actor_id,
    p_command,
    p_entity_type,
    p_entity_id,
    coalesce(p_payload, '{}'::jsonb)
  );
end;
$$;

revoke all on function multitenancy._admin_audit(uuid, uuid, text, text, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_audit(uuid, uuid, text, text, text, jsonb) to service_role;


-- ============================================================================
-- 2. DOMAIN HANDLER: TENANT
-- ============================================================================

create or replace function multitenancy._admin_tenant(
  p_actor_id  uuid,
  p_tenant_id uuid,
  p_is_owner  boolean,
  p_command   text,
  p_payload   jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_membership_id uuid;
  v_result        jsonb;
begin
  if not p_is_owner then
    raise exception 'FORBIDDEN: only owner can update tenant' using errcode = '42501';
  end if;

  case p_command
    when 'tenant.update' then
      update multitenancy.tenants
      set
        name       = coalesce(p_payload->>'name', name),
        slug       = coalesce(lower(p_payload->>'slug'), slug),
        updated_at = now()
      where id = p_tenant_id
      returning jsonb_build_object('id', id, 'slug', slug, 'name', name) into v_result;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'tenant', p_tenant_id::text, p_payload
      );
      return v_result;

    when 'tenant.deactivate' then
      update multitenancy.tenants
      set
        is_active  = false,
        updated_at = now()
      where id = p_tenant_id;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'tenant', p_tenant_id::text
      );
      return jsonb_build_object('tenant_id', p_tenant_id, 'is_active', false);

    when 'tenant.reactivate' then
      update multitenancy.tenants
      set
        is_active  = true,
        updated_at = now()
      where id = p_tenant_id;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'tenant', p_tenant_id::text
      );
      return jsonb_build_object('tenant_id', p_tenant_id, 'is_active', true);

    when 'tenant.transfer_ownership' then
      v_membership_id := (p_payload->>'new_owner_user_id')::uuid;
      if v_membership_id is null then
        raise exception 'INVALID_INPUT: new_owner_user_id required' using errcode = '22P02';
      end if;

      if not exists (
        select 1 from multitenancy.memberships
        where tenant_id = p_tenant_id
          and user_id   = v_membership_id
          and status    = 'active'
      ) then
        raise exception 'INVALID_INPUT: new owner must be active member' using errcode = '22P02';
      end if;

      update multitenancy.tenants
      set
        owner_user_id = v_membership_id,
        updated_at    = now()
      where id = p_tenant_id;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'tenant', p_tenant_id::text,
        jsonb_build_object('new_owner', v_membership_id)
      );
      return jsonb_build_object('tenant_id', p_tenant_id, 'owner_user_id', v_membership_id);

    else
      raise exception 'INVALID_INPUT: unknown command %', p_command using errcode = '22P02';
  end case;
end;
$$;

revoke all on function multitenancy._admin_tenant(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_tenant(uuid, uuid, boolean, text, jsonb) to service_role;
