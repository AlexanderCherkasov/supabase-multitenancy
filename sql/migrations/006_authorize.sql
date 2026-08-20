-- 006_authorize.sql
-- supabase-multitenancy v0.3.0 — Authorization helpers and internal RLS lockdown
-- Purpose: Resolve a user's effective permission level without inspecting app rows.
-- Dependencies: 002_identities, 003_rbac, 004_invitations, 005_audit

alter table multitenancy.profiles enable row level security;
alter table multitenancy.tenants enable row level security;
alter table multitenancy.scopes enable row level security;
alter table multitenancy.memberships enable row level security;
alter table multitenancy.permissions enable row level security;
alter table multitenancy.roles enable row level security;
alter table multitenancy.role_permissions enable row level security;
alter table multitenancy.role_assignments enable row level security;
alter table multitenancy.invitations enable row level security;
alter table multitenancy.invitation_grants enable row level security;
alter table multitenancy.audit_events enable row level security;
alter table multitenancy.settings enable row level security;
alter table multitenancy.package_meta enable row level security;

do $$
declare t text;
begin
  foreach t in array array[
    'profiles','tenants','scopes','memberships','permissions','roles',
    'role_permissions','role_assignments','invitations','invitation_grants',
    'audit_events','settings','package_meta'] loop
    execute format('drop policy if exists "service_role all" on multitenancy.%I', t);
    execute format('create policy "service_role all" on multitenancy.%I for all to service_role using (true) with check (true)', t);
  end loop;
end$$;

-- Effective access is a strict lattice: none < own < all. For multiple scopes,
-- every requested scope must be covered; the weakest covered scope wins.
create or replace function multitenancy.access_level(
  p_tenant_id uuid,
  p_permission text,
  p_scope_ids uuid[] default null
)
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_permission_id uuid;
  v_membership_id uuid;
  v_scope_id uuid;
  v_rank integer;
  v_effective_rank integer := 2;
begin
  if v_uid is null or p_tenant_id is null or p_permission is null then
    return 'none';
  end if;

  select p.id into v_permission_id
  from multitenancy.permissions p
  where p.key = p_permission and not p.is_deprecated;
  if v_permission_id is null then return 'none'; end if;

  if not exists (
    select 1 from multitenancy.tenants t
    where t.id = p_tenant_id and t.is_active
  ) then return 'none'; end if;

  select m.id into v_membership_id
  from multitenancy.memberships m
  where m.tenant_id = p_tenant_id and m.user_id = v_uid and m.status = 'active';
  if v_membership_id is null then return 'none'; end if;

  if exists (
    select 1 from multitenancy.tenants t
    where t.id = p_tenant_id and t.owner_user_id = v_uid
  ) then return 'all'; end if;

  if p_scope_ids is null or cardinality(p_scope_ids) = 0 then
    select max(case rp.access_level when 'all' then 2 when 'own' then 1 else 0 end)
      into v_rank
    from multitenancy.role_assignments ra
    join multitenancy.role_permissions rp on rp.role_id = ra.role_id
    where ra.membership_id = v_membership_id
      and ra.tenant_id = p_tenant_id
      and ra.scope_id is null
      and rp.permission_id = v_permission_id;
    return case coalesce(v_rank, 0) when 2 then 'all' when 1 then 'own' else 'none' end;
  end if;

  if array_position(p_scope_ids, null) is not null then return 'none'; end if;

  foreach v_scope_id in array p_scope_ids loop
    if not exists (
      select 1 from multitenancy.scopes s
      where s.id = v_scope_id and s.tenant_id = p_tenant_id
    ) then return 'none'; end if;

    select max(case rp.access_level when 'all' then 2 when 'own' then 1 else 0 end)
      into v_rank
    from multitenancy.role_assignments ra
    join multitenancy.role_permissions rp on rp.role_id = ra.role_id
    where ra.membership_id = v_membership_id
      and ra.tenant_id = p_tenant_id
      and (ra.scope_id is null or ra.scope_id = v_scope_id)
      and rp.permission_id = v_permission_id;

    if coalesce(v_rank, 0) = 0 then return 'none'; end if;
    v_effective_rank := least(v_effective_rank, v_rank);
  end loop;

  return case v_effective_rank when 2 then 'all' when 1 then 'own' else 'none' end;
end;
$$;

create or replace function multitenancy.has_access(
  p_tenant_id uuid,
  p_permission text,
  p_scope_ids uuid[],
  p_required_level text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case p_required_level
    when 'own' then multitenancy.access_level(p_tenant_id, p_permission, p_scope_ids) in ('own', 'all')
    when 'all' then multitenancy.access_level(p_tenant_id, p_permission, p_scope_ids) = 'all'
    else false
  end
$$;

-- Backward-compatible boolean helper: true means at least `own` access.
create or replace function multitenancy.authorize(
  p_tenant_id uuid,
  p_permission text,
  p_scope_ids uuid[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.has_access(p_tenant_id, p_permission, p_scope_ids, 'own')
$$;

-- Generated table triggers use this to prevent moving a protected row between
-- tenants or scopes during UPDATE. TG_ARGV contains column names.
create or replace function multitenancy.enforce_protected_keys_immutable()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_index integer;
  v_old jsonb := to_jsonb(old);
  v_new jsonb := to_jsonb(new);
begin
  for v_index in 0..tg_nargs - 1 loop
    if v_old -> tg_argv[v_index] is distinct from v_new -> tg_argv[v_index] then
      raise exception 'PROTECTED_KEY_IMMUTABLE: %', tg_argv[v_index] using errcode = '42501';
    end if;
  end loop;
  return new;
end;
$$;

grant usage on schema multitenancy to anon, authenticated, service_role;
revoke all on function multitenancy.access_level(uuid,text,uuid[]) from public, anon;
revoke all on function multitenancy.has_access(uuid,text,uuid[],text) from public, anon;
revoke all on function multitenancy.authorize(uuid,text,uuid[]) from public, anon;
revoke all on function multitenancy.enforce_protected_keys_immutable() from public, anon;
grant execute on function multitenancy.access_level(uuid,text,uuid[]) to authenticated, service_role;
grant execute on function multitenancy.has_access(uuid,text,uuid[],text) to authenticated, service_role;
grant execute on function multitenancy.authorize(uuid,text,uuid[]) to authenticated, service_role;
grant execute on function multitenancy.enforce_protected_keys_immutable() to authenticated, service_role;

comment on function multitenancy.access_level(uuid,text,uuid[]) is
  'Returns none, own, or all using live tenant membership and role assignments.';
