-- 013_admin_member.sql
-- supabase-multitenancy v0.3.0 — Member administration routines
-- Purpose: Private handlers for member grants, suspension, reactivation, and removal.
-- Dependencies: 003_rbac, 006_authorize, 011_admin_tenant

-- ============================================================================
-- DOMAIN HANDLER: MEMBER
-- ============================================================================

create or replace function multitenancy._admin_member(
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
  v_membership_id  uuid := (p_payload->>'membership_id')::uuid;
  v_member_user_id uuid;
  v_owner_user_id  uuid;
begin
  select user_id into v_member_user_id
  from multitenancy.memberships
  where id        = v_membership_id
    and tenant_id = p_tenant_id;

  if v_member_user_id is null then
    raise exception 'NOT_FOUND' using errcode = '42704';
  end if;

  select owner_user_id into v_owner_user_id
  from multitenancy.tenants
  where id = p_tenant_id;

  case p_command
    when 'member.set_grants' then
      if exists (
        select 1
        from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
        where (nullif(g->>'role_id', '') is null) = (nullif(g->>'role_key', '') is null)
      ) then
        raise exception 'INVALID_INPUT: exactly one of role_id or role_key is required' using errcode = '22P02';
      end if;

      if v_member_user_id = v_owner_user_id then
        raise exception 'FORBIDDEN: cannot modify owner grants' using errcode = '42501';
      end if;

      if not p_is_owner then
        if not multitenancy.authorize(p_tenant_id, 'multitenancy.members.manage', null) then
          raise exception 'FORBIDDEN' using errcode = '42501';
        end if;

        if exists (
          select 1
          from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
          join multitenancy.roles r on (
            r.id = nullif(g->>'role_id', '')::uuid
            or r.key = nullif(g->>'role_key', '')
          )
          join multitenancy.role_permissions rp on rp.role_id = r.id
          join multitenancy.permissions perm on perm.id = rp.permission_id
          where (r.tenant_id is not null and r.tenant_id <> p_tenant_id)
             or not multitenancy.has_access(
                  p_tenant_id,
                  perm.key,
                  case when nullif(g->>'scope_id', '') is not null then array[(g->>'scope_id')::uuid] else null end,
                  rp.access_level
                )
        ) then
          raise exception 'ROLE_ESCALATION' using errcode = '42501';
        end if;
      end if;

      delete from multitenancy.role_assignments where membership_id = v_membership_id;

      insert into multitenancy.role_assignments (tenant_id, membership_id, role_id, scope_id)
      select
        p_tenant_id,
        v_membership_id,
        r.id,
        nullif(g->>'scope_id', '')::uuid
      from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
      join multitenancy.roles r on (
        r.id = nullif(g->>'role_id', '')::uuid
        or r.key = nullif(g->>'role_key', '')
      ) and (r.tenant_id is null or r.tenant_id = p_tenant_id)
      on conflict do nothing;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'membership', v_membership_id::text, p_payload
      );
      return jsonb_build_object('membership_id', v_membership_id, 'grants', p_payload->'grants');

    when 'member.suspend' then
      if not p_is_owner and not multitenancy.authorize(p_tenant_id, 'multitenancy.members.manage', null) then
        raise exception 'FORBIDDEN' using errcode = '42501';
      end if;

      if v_member_user_id = v_owner_user_id then
        raise exception 'FORBIDDEN: cannot suspend owner' using errcode = '42501';
      end if;

      update multitenancy.memberships
      set
        status     = 'suspended',
        updated_at = now()
      where id        = v_membership_id
        and tenant_id = p_tenant_id;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'membership', v_membership_id::text
      );
      return jsonb_build_object('membership_id', v_membership_id, 'status', 'suspended');

    when 'member.reactivate' then
      if not p_is_owner and not multitenancy.authorize(p_tenant_id, 'multitenancy.members.manage', null) then
        raise exception 'FORBIDDEN' using errcode = '42501';
      end if;

      update multitenancy.memberships
      set
        status     = 'active',
        updated_at = now()
      where id        = v_membership_id
        and tenant_id = p_tenant_id;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'membership', v_membership_id::text
      );
      return jsonb_build_object('membership_id', v_membership_id, 'status', 'active');

    when 'member.remove' then
      if not p_is_owner and not multitenancy.authorize(p_tenant_id, 'multitenancy.members.manage', null) then
        raise exception 'FORBIDDEN' using errcode = '42501';
      end if;

      if v_member_user_id = v_owner_user_id then
        raise exception 'FORBIDDEN: cannot remove owner' using errcode = '42501';
      end if;

      update multitenancy.memberships
      set
        status     = 'removed',
        updated_at = now()
      where id        = v_membership_id
        and tenant_id = p_tenant_id;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      delete from multitenancy.role_assignments where membership_id = v_membership_id;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'membership', v_membership_id::text
      );
      return jsonb_build_object('membership_id', v_membership_id, 'status', 'removed');

    else
      raise exception 'INVALID_INPUT: unknown command %', p_command using errcode = '22P02';
  end case;
end;
$$;

revoke all on function multitenancy._admin_member(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_member(uuid, uuid, boolean, text, jsonb) to service_role;
