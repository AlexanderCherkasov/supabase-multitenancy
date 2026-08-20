-- 012_admin_scope.sql
-- supabase-multitenancy v0.3.0 — Scope administration routines
-- Purpose: Private handlers for creating, updating, and deleting project scopes.
-- Dependencies: 002_identities, 006_authorize, 011_admin_tenant

-- ============================================================================
-- DOMAIN HANDLER: SCOPE
-- ============================================================================

create or replace function multitenancy._admin_scope(
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
  v_scope_id uuid;
  v_result   jsonb;
begin
  if not p_is_owner and not multitenancy.authorize(p_tenant_id, 'multitenancy.scopes.manage', null) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  case p_command
    when 'scope.create' then
      insert into multitenancy.scopes (tenant_id, kind, key, name, metadata)
      values (
        p_tenant_id,
        p_payload->>'kind',
        p_payload->>'key',
        p_payload->>'name',
        coalesce(p_payload->'metadata', '{}'::jsonb)
      )
      returning jsonb_build_object('id', id, 'kind', kind, 'key', key, 'name', name) into v_result;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'scope', (v_result->>'id'), p_payload
      );
      return v_result;

    when 'scope.update' then
      v_scope_id := (p_payload->>'scope_id')::uuid;

      update multitenancy.scopes
      set
        name       = coalesce(p_payload->>'name', name),
        metadata   = coalesce(p_payload->'metadata', metadata),
        updated_at = now()
      where id        = v_scope_id
        and tenant_id = p_tenant_id
      returning jsonb_build_object('id', id, 'kind', kind, 'key', key, 'name', name) into v_result;

      if v_result is null then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'scope', v_scope_id::text, p_payload
      );
      return v_result;

    when 'scope.delete' then
      v_scope_id := (p_payload->>'scope_id')::uuid;

      if exists (
        select 1 from multitenancy.role_assignments where scope_id = v_scope_id
      ) then
        raise exception 'CONFLICT: scope in use by assignments' using errcode = '23505';
      end if;

      delete from multitenancy.scopes
      where id        = v_scope_id
        and tenant_id = p_tenant_id;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'scope', v_scope_id::text
      );
      return jsonb_build_object('deleted', true);

    else
      raise exception 'INVALID_INPUT: unknown command %', p_command using errcode = '22P02';
  end case;
end;
$$;

revoke all on function multitenancy._admin_scope(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_scope(uuid, uuid, boolean, text, jsonb) to service_role;
