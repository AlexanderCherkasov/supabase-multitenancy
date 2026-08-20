-- 014_admin_invitation.sql
-- supabase-multitenancy v0.3.0 — Invitation administration routines
-- Purpose: Private handlers for creating, resending, and revoking invitations.
-- Dependencies: 004_invitations, 006_authorize, 011_admin_tenant

-- ============================================================================
-- DOMAIN HANDLER: INVITATION
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
      if exists (
        select 1
        from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
        where (nullif(g->>'role_id', '') is null) = (nullif(g->>'role_key', '') is null)
      ) then
        raise exception 'INVALID_INPUT: exactly one of role_id or role_key is required' using errcode = '22P02';
      end if;

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
        r.id,
        nullif(g->>'scope_id', '')::uuid
      from jsonb_array_elements(coalesce(p_payload->'grants', '[]'::jsonb)) g
      join multitenancy.roles r on (
        r.id = nullif(g->>'role_id', '')::uuid
        or r.key = nullif(g->>'role_key', '')
      ) and (r.tenant_id is null or r.tenant_id = p_tenant_id)
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
              (r.tenant_id is not null and r.tenant_id <> p_tenant_id)
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

revoke all on function multitenancy._admin_invitation(uuid, uuid, boolean, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._admin_invitation(uuid, uuid, boolean, text, jsonb) to service_role;
