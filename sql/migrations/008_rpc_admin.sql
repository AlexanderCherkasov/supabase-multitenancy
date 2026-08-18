-- 008_rpc_admin.sql
-- supabase-multitenancy v0.2.0 — Schema RPC: admin (discriminated commands)
-- Single entry point for all tenant admin operations in `multitenancy` schema.
-- Modularized into domain-specific sub-handlers with strict security boundaries.
-- Dependencies: 007_rpc_core (authorize must exist)

drop function if exists public.multitenancy_admin(uuid, text, jsonb);

-- ============================================================================
-- 1. Helper: Internal Audit Logger
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

-- ============================================================================
-- 2. Domain Handler: TENANT
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

-- ============================================================================
-- 3. Domain Handler: SCOPE
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

-- ============================================================================
-- 4. Domain Handler: MEMBER
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
  v_membership_id uuid := (p_payload->>'membership_id')::uuid;
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
          join multitenancy.roles r on r.id = (g->>'role_id')::uuid
          join multitenancy.role_permissions rp on rp.role_id = r.id
          join multitenancy.permissions perm on perm.id = rp.permission_id
          where r.tenant_id <> p_tenant_id
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

      insert into multitenancy.role_assignments (membership_id, role_id, scope_id)
      select
        v_membership_id,
        (g->>'role_id')::uuid,
        nullif(g->>'scope_id', '')::uuid
      from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
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

-- ============================================================================
-- 5. Domain Handler: INVITATION
-- ============================================================================
create or replace function multitenancy._admin_invitation(
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
  v_invitation_id uuid;
  v_email         text;
  v_email_norm    text;
  v_raw_token     text;
  v_token_hash    text;
  v_expires_at    timestamptz;
  v_ttl           int;
begin
  if not p_is_owner and not multitenancy.authorize(p_tenant_id, 'multitenancy.members.invite', null) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  case p_command
    when 'invitation.create' then
      v_email := p_payload->>'email';
      v_email_norm := lower(trim(v_email));

      if v_email_norm !~ '^[^@]+@[^@]+\.[^@]+$' then
        raise exception 'INVALID_INPUT: invalid email' using errcode = '22P02';
      end if;

      if (select owner_user_id from multitenancy.tenants where id = p_tenant_id) =
         (select id from auth.users where lower(email) = v_email_norm) then
        raise exception 'FORBIDDEN: cannot invite owner' using errcode = '42501';
      end if;

      select invitation_ttl_hours into v_ttl from multitenancy.settings where id = 1;
      v_expires_at := now() + (v_ttl || ' hours')::interval;

      v_raw_token := encode(extensions.gen_random_bytes(32), 'base64');
      v_raw_token := replace(replace(replace(v_raw_token, '+', '-'), '/', '_'), '=', '');
      v_token_hash := encode(extensions.digest(v_raw_token, 'sha256'), 'hex');

      insert into multitenancy.invitations (
        tenant_id,
        email,
        email_normalized,
        token_hash,
        expires_at,
        inviter_user_id
      ) values (
        p_tenant_id,
        v_email,
        v_email_norm,
        v_token_hash,
        v_expires_at,
        p_actor_id
      )
      returning id into v_invitation_id;

      insert into multitenancy.invitation_grants (invitation_id, role_id, scope_id)
      select
        v_invitation_id,
        (g->>'role_id')::uuid,
        nullif(g->>'scope_id', '')::uuid
      from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
      on conflict do nothing;

      if not p_is_owner then
        if exists (
          select 1
          from multitenancy.invitation_grants ig
          join multitenancy.roles r on r.id = ig.role_id
          join multitenancy.role_permissions rp on rp.role_id = ig.role_id
          join multitenancy.permissions perm on perm.id = rp.permission_id
          where ig.invitation_id = v_invitation_id
            and (
              r.tenant_id <> p_tenant_id
              or not multitenancy.has_access(
                p_tenant_id,
                perm.key,
                case when ig.scope_id is not null then array[ig.scope_id] else null end,
                rp.access_level
              )
            )
        ) then
          raise exception 'ROLE_ESCALATION' using errcode = '42501';
        end if;
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'invitation', v_invitation_id::text,
        jsonb_build_object('email', v_email_norm, 'expires_at', v_expires_at)
      );

      return jsonb_build_object(
        'invitation_id', v_invitation_id,
        'token',         v_raw_token,
        'expires_at',    v_expires_at
      );

    when 'invitation.resend' then
      v_invitation_id := (p_payload->>'invitation_id')::uuid;

      select invitation_ttl_hours into v_ttl from multitenancy.settings where id = 1;
      v_expires_at := now() + (v_ttl || ' hours')::interval;

      v_raw_token := encode(extensions.gen_random_bytes(32), 'base64');
      v_raw_token := replace(replace(replace(v_raw_token, '+', '-'), '/', '_'), '=', '');
      v_token_hash := encode(extensions.digest(v_raw_token, 'sha256'), 'hex');

      update multitenancy.invitations
      set
        token_hash = v_token_hash,
        expires_at = v_expires_at,
        revoked_at = null,
        updated_at = now()
      where id          = v_invitation_id
        and tenant_id   = p_tenant_id
        and accepted_at is null
      returning email into v_email;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'invitation', v_invitation_id::text,
        jsonb_build_object('expires_at', v_expires_at)
      );

      return jsonb_build_object(
        'invitation_id', v_invitation_id,
        'token',         v_raw_token,
        'expires_at',    v_expires_at
      );

    when 'invitation.revoke' then
      v_invitation_id := (p_payload->>'invitation_id')::uuid;

      update multitenancy.invitations
      set
        revoked_at = now(),
        updated_at = now()
      where id          = v_invitation_id
        and tenant_id   = p_tenant_id
        and accepted_at is null;

      if not found then
        raise exception 'NOT_FOUND' using errcode = '42704';
      end if;

      perform multitenancy._admin_audit(
        p_tenant_id, p_actor_id, p_command, 'invitation', v_invitation_id::text
      );

      return jsonb_build_object('invitation_id', v_invitation_id, 'revoked', true);

    else
      raise exception 'INVALID_INPUT: unknown command %', p_command using errcode = '22P02';
  end case;
end;
$$;

-- ============================================================================
-- 6. Main Dispatcher: admin
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
  v_uid      uuid;
  v_is_owner boolean;
  v_data     jsonb;
begin
  v_uid := auth.uid();
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  select (owner_user_id = v_uid) into v_is_owner
  from multitenancy.tenants
  where id = p_tenant_id;

  if v_is_owner is null then
    raise exception 'NOT_FOUND' using errcode = '42704';
  end if;

  if p_command like 'role.%' then
    raise exception 'FORBIDDEN: roles and role permissions are DBA-managed' using errcode = '42501';
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

-- Security Grants & Revocations
revoke all on function multitenancy._admin_audit(uuid, uuid, text, text, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_audit(uuid, uuid, text, text, text, jsonb) to service_role;

revoke all on function multitenancy._admin_tenant(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_tenant(uuid, uuid, boolean, text, jsonb) to service_role;

revoke all on function multitenancy._admin_scope(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_scope(uuid, uuid, boolean, text, jsonb) to service_role;

revoke all on function multitenancy._admin_member(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_member(uuid, uuid, boolean, text, jsonb) to service_role;

revoke all on function multitenancy._admin_invitation(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_invitation(uuid, uuid, boolean, text, jsonb) to service_role;

revoke all on function multitenancy.admin(uuid, text, jsonb) from public, anon;
grant execute on function multitenancy.admin(uuid, text, jsonb) to authenticated, service_role;

update multitenancy.package_meta set version = '0.2.0', installed_at = now() where id = 1;
