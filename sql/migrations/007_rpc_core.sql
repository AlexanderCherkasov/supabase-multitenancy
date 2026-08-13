-- 007_rpc_core.sql
-- supabase-multitenancy v0.2.0 — Schema RPCs: create_tenant, can, context, preview, accept
-- All RPCs reside in `multitenancy` schema, return { api_version: 1, data: ... }, and are SECURITY DEFINER.
-- Dependencies: 006_authorize

drop function if exists public.multitenancy_create_tenant(text, text);
drop function if exists public.multitenancy_can(uuid, text, uuid[]);
drop function if exists public.multitenancy_context(uuid, text, text, int);
drop function if exists public.multitenancy_invitation_preview(text);
drop function if exists public.multitenancy_accept_invitation(text);

-- ============= create_tenant =============
create or replace function multitenancy.create_tenant(p_slug text, p_name text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_uid uuid; v_tenant_id uuid; v_slug text;
begin
  v_uid := auth.uid();
  if v_uid is null then raise exception 'UNAUTHENTICATED' using errcode='28000'; end if;
  if not coalesce((select self_service_tenant_creation from multitenancy.settings where id=1), false) then
    raise exception 'FORBIDDEN: self-service tenant creation is disabled' using errcode='42501';
  end if;
  v_slug := lower(p_slug);
  if v_slug !~ '^[a-z0-9-]{3,40}$' then raise exception 'INVALID_INPUT: slug must match ^[a-z0-9-]{3,40}$' using errcode='22P02'; end if;
  if char_length(p_name) not between 2 and 120 then raise exception 'INVALID_INPUT: name length 2..120' using errcode='22P02'; end if;
  insert into multitenancy.tenants (slug, name, owner_user_id) values (v_slug, p_name, v_uid) returning id into v_tenant_id;
  insert into multitenancy.profiles (user_id) values (v_uid) on conflict (user_id) do nothing;
  insert into multitenancy.memberships (tenant_id, user_id, status) values (v_tenant_id, v_uid, 'active')
  on conflict (tenant_id, user_id) do update set status='active', updated_at=now();
  insert into multitenancy.audit_events (tenant_id, actor_user_id, command, entity_type, entity_id, payload)
  values (v_tenant_id, v_uid, 'tenant.create', 'tenant', v_tenant_id::text, jsonb_build_object('slug', v_slug, 'name', p_name));
  return jsonb_build_object('api_version',1,'data',jsonb_build_object('tenant_id',v_tenant_id,'slug',v_slug,'name',p_name));
exception when unique_violation then raise exception 'CONFLICT: slug already exists' using errcode='23505';
end;
$$;
revoke all on function multitenancy.create_tenant(text,text) from public, anon;
grant execute on function multitenancy.create_tenant(text,text) to authenticated, service_role;

-- ============= can (UI helper, not RLS replacement) =============
create or replace function multitenancy.can(p_tenant_id uuid, p_permission text, p_scope_ids uuid[])
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_allowed boolean;
begin
  if auth.uid() is null then raise exception 'UNAUTHENTICATED' using errcode='28000'; end if;
  v_allowed := multitenancy.authorize(p_tenant_id, p_permission, p_scope_ids);
  return jsonb_build_object('api_version',1,'data',jsonb_build_object('allowed',v_allowed));
end;
$$;
revoke all on function multitenancy.can(uuid,text,uuid[]) from public, anon;
grant execute on function multitenancy.can(uuid,text,uuid[]) to authenticated, service_role;

-- ============= context (paginated sections) =============
create or replace function multitenancy.context(
  p_tenant_id uuid, p_section text, p_cursor text default null, p_limit int default 50)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_uid uuid; v_result jsonb;
begin
  v_uid := auth.uid();
  if v_uid is null then raise exception 'UNAUTHENTICATED' using errcode='28000'; end if;
  if not exists (select 1 from multitenancy.memberships where tenant_id=p_tenant_id and user_id=v_uid and status='active')
     and not exists (select 1 from multitenancy.tenants where id=p_tenant_id and owner_user_id=v_uid) then
    raise exception 'FORBIDDEN' using errcode='42501';
  end if;
  p_limit := least(greatest(coalesce(p_limit,50),1),100);
  case p_section
    when 'self' then
      select jsonb_build_object(
        'tenant', (select row_to_json(t) from (select id, slug, name, owner_user_id, is_active from multitenancy.tenants where id=p_tenant_id) t),
        'membership', (select row_to_json(m) from (select id, status from multitenancy.memberships where tenant_id=p_tenant_id and user_id=v_uid) m),
        'is_owner', (select owner_user_id=v_uid from multitenancy.tenants where id=p_tenant_id)
      ) into v_result;
    when 'permissions' then
      select coalesce(jsonb_agg(row_to_json(p)),'[]'::jsonb) into v_result
      from (select key, origin, is_deprecated from multitenancy.permissions order by key limit p_limit) p;
    when 'scopes' then
      select coalesce(jsonb_agg(row_to_json(s)),'[]'::jsonb) into v_result
      from (select id, kind, key, name from multitenancy.scopes where tenant_id=p_tenant_id order by kind, key limit p_limit) s;
    when 'roles' then
      select coalesce(jsonb_agg(row_to_json(r)),'[]'::jsonb) into v_result
      from (select rl.id, rl.key, rl.name, rl.description,
              (select jsonb_agg(jsonb_build_object('key',perm.key,'access_level',rp.access_level) order by perm.key)
                 from multitenancy.role_permissions rp
                 join multitenancy.permissions perm on perm.id=rp.permission_id
                where rp.role_id=rl.id) as permissions
            from multitenancy.roles rl where rl.tenant_id=p_tenant_id order by rl.key limit p_limit) r;
    when 'members' then
      if not multitenancy.authorize(p_tenant_id,'multitenancy.members.read',null) and (select owner_user_id from multitenancy.tenants where id=p_tenant_id) <> v_uid then
        raise exception 'FORBIDDEN' using errcode='42501';
      end if;
      select coalesce(jsonb_agg(row_to_json(m)),'[]'::jsonb) into v_result
      from (select mem.id, mem.user_id, mem.status, prof.display_name,
              (select jsonb_agg(jsonb_build_object('role_id',ra.role_id,'scope_id',ra.scope_id)) from multitenancy.role_assignments ra where ra.membership_id=mem.id) as grants
            from multitenancy.memberships mem left join multitenancy.profiles prof on prof.user_id=mem.user_id
            where mem.tenant_id=p_tenant_id order by mem.created_at limit p_limit) m;
    when 'invitations' then
      if not multitenancy.authorize(p_tenant_id,'multitenancy.members.read',null) and (select owner_user_id from multitenancy.tenants where id=p_tenant_id) <> v_uid then
        raise exception 'FORBIDDEN' using errcode='42501';
      end if;
      select coalesce(jsonb_agg(row_to_json(inv)),'[]'::jsonb) into v_result
      from (select id, email, email_normalized, expires_at, revoked_at, accepted_at, created_at from multitenancy.invitations where tenant_id=p_tenant_id order by created_at desc limit p_limit) inv;
    when 'audit' then
      if not multitenancy.authorize(p_tenant_id,'multitenancy.audit.read',null) and (select owner_user_id from multitenancy.tenants where id=p_tenant_id) <> v_uid then
        raise exception 'FORBIDDEN' using errcode='42501';
      end if;
      select coalesce(jsonb_agg(row_to_json(a)),'[]'::jsonb) into v_result
      from (select id, actor_user_id, command, entity_type, entity_id, payload, created_at from multitenancy.audit_events where tenant_id=p_tenant_id order by created_at desc limit p_limit) a;
    else raise exception 'INVALID_INPUT: unknown section %', p_section using errcode='22P02';
  end case;
  return jsonb_build_object('api_version',1,'data',v_result);
end;
$$;
revoke all on function multitenancy.context(uuid,text,text,int) from public, anon;
grant execute on function multitenancy.context(uuid,text,text,int) to authenticated, service_role;

-- ============= invitation_preview (anon + authenticated) =============
create or replace function multitenancy.invitation_preview(p_token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_hash text; v_row record; v_masked text;
begin
  if p_token is null or char_length(p_token) < 20 then raise exception 'TOKEN_INVALID' using errcode='28000'; end if;
  v_hash := encode(extensions.digest(p_token,'sha256'),'hex');
  select i.email, i.expires_at, i.revoked_at, i.accepted_at, t.name as tenant_name, t.id as tenant_id,
         (select jsonb_agg(jsonb_build_object('role',r.key,'scope_id',ig.scope_id)) from multitenancy.invitation_grants ig join multitenancy.roles r on r.id=ig.role_id where ig.invitation_id=i.id) as grants
  into v_row from multitenancy.invitations i join multitenancy.tenants t on t.id=i.tenant_id where i.token_hash=v_hash;
  if not found then raise exception 'TOKEN_INVALID' using errcode='28000'; end if;
  if v_row.accepted_at is not null then raise exception 'TOKEN_ACCEPTED' using errcode='28000'; end if;
  if v_row.revoked_at is not null then raise exception 'TOKEN_REVOKED' using errcode='28000'; end if;
  if v_row.expires_at < now() then raise exception 'TOKEN_EXPIRED' using errcode='28000'; end if;
  v_masked := regexp_replace(v_row.email,'(.).*(@.*)','\1***\2');
  return jsonb_build_object('api_version',1,'data',jsonb_build_object('tenant_id',v_row.tenant_id,'tenant_name',v_row.tenant_name,'email_masked',v_masked,'expires_at',v_row.expires_at,'grants',coalesce(v_row.grants,'[]'::jsonb),'valid',true));
end;
$$;
revoke all on function multitenancy.invitation_preview(text) from public, anon;
grant execute on function multitenancy.invitation_preview(text) to anon, authenticated, service_role;

-- ============= accept_invitation =============
create or replace function multitenancy.accept_invitation(p_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_uid uuid; v_email text; v_hash text; v_inv record; v_membership_id uuid;
begin
  v_uid := auth.uid();
  if v_uid is null then raise exception 'UNAUTHENTICATED' using errcode='28000'; end if;
  select email into v_email from auth.users where id=v_uid;
  if v_email is null then raise exception 'UNAUTHENTICATED' using errcode='28000'; end if;
  v_hash := encode(extensions.digest(p_token,'sha256'),'hex');
  select * into v_inv from multitenancy.invitations where token_hash=v_hash for update;
  if not found then raise exception 'TOKEN_INVALID' using errcode='28000'; end if;
  if v_inv.accepted_at is not null and v_inv.accepted_by_user_id=v_uid then
    return jsonb_build_object('api_version',1,'data',jsonb_build_object('tenant_id',v_inv.tenant_id,'membership_id',(select id from multitenancy.memberships where tenant_id=v_inv.tenant_id and user_id=v_uid)));
  end if;
  if v_inv.accepted_at is not null then raise exception 'TOKEN_INVALID: already accepted' using errcode='28000'; end if;
  if lower(v_email) <> lower(v_inv.email_normalized) and lower(v_email) <> lower(v_inv.email) then raise exception 'EMAIL_MISMATCH' using errcode='42501'; end if;
  if v_inv.revoked_at is not null then raise exception 'TOKEN_REVOKED' using errcode='28000'; end if;
  if v_inv.expires_at < now() then raise exception 'TOKEN_EXPIRED' using errcode='28000'; end if;
  if (select owner_user_id from multitenancy.tenants where id=v_inv.tenant_id)=v_uid then raise exception 'FORBIDDEN: owner cannot accept invitation' using errcode='42501'; end if;
  insert into multitenancy.profiles (user_id) values (v_uid) on conflict (user_id) do nothing;
  insert into multitenancy.memberships (tenant_id, user_id, status) values (v_inv.tenant_id, v_uid, 'active')
  on conflict (tenant_id, user_id) do update set status='active', updated_at=now() returning id into v_membership_id;
  insert into multitenancy.role_assignments (membership_id, role_id, scope_id)
    select v_membership_id, ig.role_id, ig.scope_id from multitenancy.invitation_grants ig where ig.invitation_id=v_inv.id on conflict do nothing;
  update multitenancy.invitations set accepted_at=now(), accepted_by_user_id=v_uid, updated_at=now() where id=v_inv.id;
  insert into multitenancy.audit_events (tenant_id, actor_user_id, command, entity_type, entity_id, payload)
  values (v_inv.tenant_id, v_uid, 'invitation.accept','invitation',v_inv.id::text, jsonb_build_object('email',v_inv.email));
  return jsonb_build_object('api_version',1,'data',jsonb_build_object('tenant_id',v_inv.tenant_id,'membership_id',v_membership_id));
end;
$$;
revoke all on function multitenancy.accept_invitation(text) from public, anon;
grant execute on function multitenancy.accept_invitation(text) to authenticated, service_role;

-- Version bump
update multitenancy.package_meta set version='0.2.0', installed_at=now() where id=1;
