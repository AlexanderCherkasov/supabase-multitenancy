-- 010_rpc_invitations.sql
-- supabase-multitenancy v0.3.0 — Invitation acceptance & preview RPCs
-- Purpose: Token verification, anonymous preview, and atomic acceptance.
-- Dependencies: 004_invitations, 006_authorize

-- ============================================================================
-- 1. INVITATION PREVIEW (ANON + AUTHENTICATED)
-- ============================================================================

create or replace function multitenancy.invitation_preview(
  p_token text
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_hash   text;
  v_row    record;
  v_masked text;
begin
  if p_token is null or char_length(p_token) < 20 then
    raise exception 'TOKEN_INVALID' using errcode = '28000';
  end if;

  v_hash := encode(extensions.digest(p_token, 'sha256'), 'hex');

  select
    i.email,
    i.expires_at,
    i.revoked_at,
    i.accepted_at,
    t.name as tenant_name,
    t.id as tenant_id,
    (
      select jsonb_agg(jsonb_build_object('role', r.key, 'scope_id', ig.scope_id))
      from multitenancy.invitation_grants ig
      join multitenancy.roles r on r.id = ig.role_id
      where ig.invitation_id = i.id
    ) as grants
  into v_row
  from multitenancy.invitations i
  join multitenancy.tenants t on t.id = i.tenant_id
  where i.token_hash = v_hash;

  if not found then
    raise exception 'TOKEN_INVALID' using errcode = '28000';
  end if;

  if v_row.accepted_at is not null then
    raise exception 'TOKEN_ACCEPTED' using errcode = '28000';
  end if;

  if v_row.revoked_at is not null then
    raise exception 'TOKEN_REVOKED' using errcode = '28000';
  end if;

  if v_row.expires_at < now() then
    raise exception 'TOKEN_EXPIRED' using errcode = '28000';
  end if;

  v_masked := regexp_replace(v_row.email, '(.).*(@.*)', '\1***\2');

  return jsonb_build_object(
    'api_version', 1,
    'data', jsonb_build_object(
      'tenant_id',   v_row.tenant_id,
      'tenant_name', v_row.tenant_name,
      'email_masked', v_masked,
      'expires_at',  v_row.expires_at,
      'grants',      coalesce(v_row.grants, '[]'::jsonb),
      'valid',       true
    )
  );
end;
$$;

revoke all on function multitenancy.invitation_preview(text) from public, anon;
grant execute on function multitenancy.invitation_preview(text) to anon, authenticated, service_role;


-- ============================================================================
-- 2. INVITATION ACCEPTANCE
-- ============================================================================

create or replace function multitenancy.accept_invitation(
  p_token text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid           uuid := auth.uid();
  v_email         text;
  v_hash          text;
  v_inv           record;
  v_membership_id uuid;
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  select email into v_email
  from auth.users
  where id = v_uid;

  if v_email is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  v_hash := encode(extensions.digest(p_token, 'sha256'), 'hex');

  select * into v_inv
  from multitenancy.invitations
  where token_hash = v_hash
  for update;

  if not found then
    raise exception 'TOKEN_INVALID' using errcode = '28000';
  end if;

  if v_inv.accepted_at is not null and v_inv.accepted_by_user_id = v_uid then
    return jsonb_build_object(
      'api_version', 1,
      'data', jsonb_build_object(
        'tenant_id',     v_inv.tenant_id,
        'membership_id', (
          select id from multitenancy.memberships
          where tenant_id = v_inv.tenant_id and user_id = v_uid
        )
      )
    );
  end if;

  if v_inv.accepted_at is not null then
    raise exception 'TOKEN_INVALID: already accepted' using errcode = '28000';
  end if;

  if lower(v_email) <> lower(v_inv.email_normalized) and lower(v_email) <> lower(v_inv.email) then
    raise exception 'EMAIL_MISMATCH' using errcode = '42501';
  end if;

  if v_inv.revoked_at is not null then
    raise exception 'TOKEN_REVOKED' using errcode = '28000';
  end if;

  if v_inv.expires_at < now() then
    raise exception 'TOKEN_EXPIRED' using errcode = '28000';
  end if;

  if (select owner_user_id from multitenancy.tenants where id = v_inv.tenant_id) = v_uid then
    raise exception 'FORBIDDEN: owner cannot accept invitation' using errcode = '42501';
  end if;

  insert into multitenancy.profiles (user_id)
  values (v_uid)
  on conflict (user_id) do nothing;

  insert into multitenancy.memberships (tenant_id, user_id, status)
  values (v_inv.tenant_id, v_uid, 'active')
  on conflict (tenant_id, user_id)
  do update set status = 'active', updated_at = now()
  returning id into v_membership_id;

  insert into multitenancy.role_assignments (tenant_id, membership_id, role_id, scope_id)
  select v_inv.tenant_id, v_membership_id, ig.role_id, ig.scope_id
  from multitenancy.invitation_grants ig
  where ig.invitation_id = v_inv.id
  on conflict do nothing;

  update multitenancy.invitations
  set accepted_at = now(),
      accepted_by_user_id = v_uid,
      updated_at = now()
  where id = v_inv.id;

  insert into multitenancy.audit_events (
    tenant_id, actor_user_id, command, entity_type, entity_id, payload
  )
  values (
    v_inv.tenant_id, v_uid, 'invitation.accept', 'invitation', v_inv.id::text,
    jsonb_build_object('email', v_inv.email)
  );

  return jsonb_build_object(
    'api_version', 1,
    'data', jsonb_build_object(
      'tenant_id',     v_inv.tenant_id,
      'membership_id', v_membership_id
    )
  );
end;
$$;

revoke all on function multitenancy.accept_invitation(text) from public, anon;
grant execute on function multitenancy.accept_invitation(text) to authenticated, service_role;
