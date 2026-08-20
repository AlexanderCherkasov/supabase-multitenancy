-- Generated release artifact. Do not edit; edit sql/migrations instead.
-- supabase-multitenancy v0.3.0

-- BEGIN 001_base.sql
-- 001_base.sql
-- supabase-multitenancy v0.3.0 — Base: extensions, schema, helpers, version
-- Purpose: Create private schema and shared utilities. No business tables.
-- Apply first. Idempotent.

create extension if not exists "pgcrypto" with schema extensions;

create schema if not exists multitenancy;

-- Shared trigger: keep updated_at fresh
create or replace function multitenancy.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;

-- Package version (single row, id=1)
create table if not exists multitenancy.package_meta (
  id int primary key check (id = 1),
  version text not null,
  installed_at timestamptz not null default now()
);
insert into multitenancy.package_meta (id, version)
values (1, '0.3.0')
on conflict (id) do update set version = excluded.version;

-- Global settings (single row, id=1)
create table if not exists multitenancy.settings (
  id int primary key check (id = 1),
  self_service_tenant_creation boolean not null default true,
  invitation_ttl_hours int not null default 168
    check (invitation_ttl_hours between 1 and 720),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
drop trigger if exists trg_settings_touch on multitenancy.settings;
create trigger trg_settings_touch
  before update on multitenancy.settings
  for each row execute function multitenancy.touch_updated_at();
insert into multitenancy.settings (id) values (1) on conflict (id) do nothing;
-- END 001_base.sql

-- BEGIN 002_identities.sql
-- 002_identities.sql
-- supabase-multitenancy v0.3.0 — Identities: profiles, tenants, scopes, memberships
-- Purpose: Tenant and membership roots. auth.users is the sole identity source.
-- Dependencies: 001_base

-- ---------------------------------------------------------------------------
-- profiles — minimal 1:1 with auth.users, auto-created via trigger
-- Does NOT conflict with an existing public.profiles table.
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
drop trigger if exists trg_profiles_touch on multitenancy.profiles;
create trigger trg_profiles_touch
  before update on multitenancy.profiles
  for each row execute function multitenancy.touch_updated_at();
create index if not exists idx_profiles_display_name on multitenancy.profiles(display_name);

create or replace function multitenancy.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into multitenancy.profiles (user_id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)))
  on conflict (user_id) do nothing;
  return new;
end;
$$;
revoke all on function multitenancy.handle_new_user() from public, anon;
grant execute on function multitenancy.handle_new_user() to service_role;
-- Use a package-owned trigger name. Never replace a consumer's conventional
-- `on_auth_user_created` trigger: PostgreSQL supports multiple AFTER triggers.
drop trigger if exists multitenancy_on_auth_user_created on auth.users;
create trigger multitenancy_on_auth_user_created after insert on auth.users
  for each row execute function multitenancy.handle_new_user();

-- ---------------------------------------------------------------------------
-- tenants — logical tenant (namespace). Lowercase slug, one owner (system state)
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.tenants (
  id uuid primary key default gen_random_uuid(),
  slug text not null check (slug ~ '^[a-z0-9-]{3,40}$'),
  name text not null check (char_length(name) between 2 and 120),
  owner_user_id uuid not null references auth.users(id),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(slug)
);
create unique index if not exists uq_tenants_slug_lower on multitenancy.tenants(lower(slug));
create index if not exists idx_tenants_owner on multitenancy.tenants(owner_user_id);
drop trigger if exists trg_tenants_touch on multitenancy.tenants;
create trigger trg_tenants_touch before update on multitenancy.tenants
  for each row execute function multitenancy.touch_updated_at();

-- ---------------------------------------------------------------------------
-- scopes — flat typed scopes per tenant (e.g., project, warehouse, client)
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.scopes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  kind text not null check (kind ~ '^[a-z][a-z0-9_]{1,39}$'),
  key text not null check (key ~ '^[a-zA-Z0-9_-]{1,80}$'),
  name text not null check (char_length(name) between 1 and 120),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, kind, key)
);
-- Composite unique for FK target (tenant_id, id) — lets app tables FK both columns
create unique index if not exists uq_scopes_tenant_id on multitenancy.scopes(tenant_id, id);
create index if not exists idx_scopes_tenant_kind on multitenancy.scopes(tenant_id, kind);
drop trigger if exists trg_scopes_touch on multitenancy.scopes;
create trigger trg_scopes_touch before update on multitenancy.scopes
  for each row execute function multitenancy.touch_updated_at();

-- ---------------------------------------------------------------------------
-- memberships — user ↔ tenant, active|suspended|removed
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.memberships (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'active' check (status in ('active','suspended','removed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, user_id),
  unique(tenant_id, id)
);
create index if not exists idx_memberships_tenant on multitenancy.memberships(tenant_id);
create index if not exists idx_memberships_user on multitenancy.memberships(user_id);
create index if not exists idx_memberships_tenant_user_status on multitenancy.memberships(tenant_id, user_id, status);
drop trigger if exists trg_memberships_touch on multitenancy.memberships;
create trigger trg_memberships_touch before update on multitenancy.memberships
  for each row execute function multitenancy.touch_updated_at();
-- END 002_identities.sql

-- BEGIN 003_rbac.sql
-- 003_rbac.sql
-- supabase-multitenancy v0.3.0 — RBAC: permissions, roles, access levels, assignments
-- Purpose: Global permission catalog + DBA-managed tenant role profiles with scoped assignments.
-- Dependencies: 002_identities

-- ---------------------------------------------------------------------------
-- permissions — global catalog `domain.action`, package vs application origin
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.permissions (
  id uuid primary key default gen_random_uuid(),
  key text not null check (key ~ '^[a-z0-9_]+\.[a-z0-9_\.]+$'),
  description text,
  origin text not null default 'application' check (origin in ('package','application')),
  is_deprecated boolean not null default false,
  created_at timestamptz not null default now(),
  unique(key)
);
create index if not exists idx_permissions_origin on multitenancy.permissions(origin);

-- Reserved package permissions (idempotent seed)
insert into multitenancy.permissions (key, origin, description) values
  ('multitenancy.tenant.manage', 'package', 'Manage tenant settings and ownership'),
  ('multitenancy.scopes.manage', 'package', 'Manage scopes'),
  ('multitenancy.members.read', 'package', 'Read members'),
  ('multitenancy.members.manage', 'package', 'Manage members and roles'),
  ('multitenancy.members.invite', 'package', 'Invite members'),
  ('multitenancy.audit.read', 'package', 'Read audit log')
on conflict (key) do nothing;

-- ---------------------------------------------------------------------------
-- roles — DBA-managed global catalog. `tenant_id` is NULL for normal global
-- roles and non-NULL only for exceptional tenant-specific DBA roles.
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.roles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references multitenancy.tenants(id) on delete cascade,
  key text not null check (key ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 120),
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(key)
);
create index if not exists idx_roles_tenant on multitenancy.roles(tenant_id);
drop trigger if exists trg_roles_touch on multitenancy.roles;
create trigger trg_roles_touch before update on multitenancy.roles
  for each row execute function multitenancy.touch_updated_at();

-- ---------------------------------------------------------------------------
-- role_permissions — which permissions a role grants
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.role_permissions (
  role_id uuid not null references multitenancy.roles(id) on delete cascade,
  permission_id uuid not null references multitenancy.permissions(id) on delete cascade,
  access_level text not null default 'all' check (access_level in ('own', 'all')),
  created_at timestamptz not null default now(),
  primary key (role_id, permission_id)
);
create index if not exists idx_role_permissions_permission on multitenancy.role_permissions(permission_id);

-- Defense in depth: even service_role cannot mutate the role catalog directly.
-- Role profiles are changed only by the database owner through migrations.
revoke all on table multitenancy.roles, multitenancy.role_permissions
  from public, anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- role_assignments — membership ↔ role, optionally scoped
-- Tenant-wide when scope_id IS NULL, otherwise scoped to one scope.
-- Multiple rows = union of permissions (user has several roles).
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.role_assignments (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  membership_id uuid not null,
  role_id uuid not null references multitenancy.roles(id) on delete cascade,
  scope_id uuid, -- nullable = tenant-wide
  created_at timestamptz not null default now(),
  unique(membership_id, role_id, scope_id),
  foreign key (tenant_id, membership_id)
    references multitenancy.memberships(tenant_id, id) on delete cascade,
  foreign key (tenant_id, scope_id)
    references multitenancy.scopes(tenant_id, id) on delete cascade
);
create index if not exists idx_role_assignments_membership on multitenancy.role_assignments(membership_id);
create index if not exists idx_role_assignments_role on multitenancy.role_assignments(role_id);
create index if not exists idx_role_assignments_scope on multitenancy.role_assignments(scope_id);
create unique index if not exists uq_role_assignments_tenant_wide
  on multitenancy.role_assignments(membership_id, role_id) where scope_id is null;

-- Enforce that role, membership, and scope all belong to the same tenant
create or replace function multitenancy.enforce_assignment_scope_tenant()
returns trigger language plpgsql security definer set search_path = '' as $$
declare v_membership_tenant uuid; v_role_tenant uuid; v_scope_tenant uuid;
begin
  select tenant_id into v_membership_tenant from multitenancy.memberships where id = new.membership_id;
  select tenant_id into v_role_tenant from multitenancy.roles where id = new.role_id;
  if v_membership_tenant is null or new.tenant_id <> v_membership_tenant then
    raise exception 'assignment tenant must match membership tenant' using errcode='23503';
  end if;
  if v_role_tenant is not null and v_role_tenant <> new.tenant_id then
    raise exception 'role is restricted to another tenant' using errcode='23503';
  end if;
  if new.scope_id is not null then
    select tenant_id into v_scope_tenant from multitenancy.scopes where id = new.scope_id;
    if v_scope_tenant is null or v_scope_tenant <> new.tenant_id then
      raise exception 'scope must belong to assignment tenant' using errcode='23503';
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists trg_assignments_scope_check on multitenancy.role_assignments;
create trigger trg_assignments_scope_check
  before insert or update on multitenancy.role_assignments
  for each row execute function multitenancy.enforce_assignment_scope_tenant();
-- END 003_rbac.sql

-- BEGIN 004_invitations.sql
-- 004_invitations.sql
-- supabase-multitenancy v0.3.0 — Invitations with one-time tokens
-- Purpose: Full lifecycle — expiry, revoke, resend, email-match, atomic accept.
-- Security: 256-bit entropy, URL-safe base64url, SHA-256 hash only, raw token once.
-- Dependencies: 003_rbac

create table if not exists multitenancy.invitations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  email text not null,               -- as typed
  email_normalized text not null,    -- lower(trim(email))
  token_hash text not null,          -- SHA-256 hex retained for terminal-state lookup
  expires_at timestamptz not null,
  revoked_at timestamptz,
  accepted_at timestamptz,
  accepted_by_user_id uuid references auth.users(id) on delete set null,
  inviter_user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_invitations_tenant_email on multitenancy.invitations(tenant_id, email_normalized);
create unique index if not exists uq_invitations_hash on multitenancy.invitations(token_hash);
-- One active invitation per (tenant, normalized_email)
create unique index if not exists uq_invitations_active_per_email
  on multitenancy.invitations(tenant_id, email_normalized)
  where revoked_at is null and accepted_at is null;
drop trigger if exists trg_invitations_touch on multitenancy.invitations;
create trigger trg_invitations_touch before update on multitenancy.invitations
  for each row execute function multitenancy.touch_updated_at();

-- Grants that will be applied on accept (additive, never removes existing)
create table if not exists multitenancy.invitation_grants (
  id uuid primary key default gen_random_uuid(),
  invitation_id uuid not null references multitenancy.invitations(id) on delete cascade,
  role_id uuid not null references multitenancy.roles(id) on delete cascade,
  scope_id uuid references multitenancy.scopes(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique(invitation_id, role_id, scope_id)
);
create unique index if not exists uq_invitation_grants_tenant_wide
  on multitenancy.invitation_grants(invitation_id, role_id) where scope_id is null;
create index if not exists idx_invitation_grants_invitation on multitenancy.invitation_grants(invitation_id);

-- Ensure invitation grants cannot reference roles or scopes from foreign tenants.
create or replace function multitenancy.enforce_invitation_grant_tenant()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_tenant_id uuid;
  v_role_tenant_id uuid;
  v_scope_tenant_id uuid;
begin
  select tenant_id into v_tenant_id
  from multitenancy.invitations
  where id = new.invitation_id;

  select tenant_id into v_role_tenant_id
  from multitenancy.roles
  where id = new.role_id;

  if v_tenant_id is null or (v_role_tenant_id is not null and v_role_tenant_id <> v_tenant_id) then
    raise exception 'role is restricted to another tenant' using errcode = '23503';
  end if;

  if new.scope_id is not null then
    select tenant_id into v_scope_tenant_id
    from multitenancy.scopes
    where id = new.scope_id;

    if v_scope_tenant_id is null or v_scope_tenant_id <> v_tenant_id then
      raise exception 'scope must belong to invitation tenant' using errcode = '23503';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists trg_invitation_grants_tenant_check on multitenancy.invitation_grants;
create trigger trg_invitation_grants_tenant_check
  before insert or update on multitenancy.invitation_grants
  for each row execute function multitenancy.enforce_invitation_grant_tenant();
-- END 004_invitations.sql

-- BEGIN 005_audit.sql
-- 005_audit.sql
-- supabase-multitenancy v0.3.0 — Audit log (append-only)
-- Purpose: Administrative command history. Never stores raw invitation tokens.
-- Dependencies: 002_identities

create table if not exists multitenancy.audit_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references multitenancy.tenants(id) on delete set null,
  -- Deliberately not an FK: deleting an auth user must not erase audit identity.
  actor_user_id uuid,
  command text not null,
  entity_type text,
  entity_id text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists idx_audit_tenant_created on multitenancy.audit_events(tenant_id, created_at desc);
create index if not exists idx_audit_actor on multitenancy.audit_events(actor_user_id);

-- Append-only: block UPDATE and DELETE
create or replace function multitenancy.prevent_audit_mutation()
returns trigger language plpgsql as $$
begin raise exception 'audit_events is append-only' using errcode='42501'; return null; end;
$$;
drop trigger if exists trg_audit_no_update on multitenancy.audit_events;
create trigger trg_audit_no_update
  before update or delete on multitenancy.audit_events
  for each row execute function multitenancy.prevent_audit_mutation();
-- END 005_audit.sql

-- BEGIN 006_authorize.sql
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

  -- Normalize scope array: strip any null values passed by single-column expressions like array[project_id]
  if p_scope_ids is not null then
    p_scope_ids := array_remove(p_scope_ids, null);
  end if;

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
-- END 006_authorize.sql

-- BEGIN 007_rpc_tenant.sql
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
-- END 007_rpc_tenant.sql

-- BEGIN 008_rpc_cursor.sql
-- 008_rpc_cursor.sql
-- supabase-multitenancy v0.3.0 — Keyset pagination cursor encoding and decoding
-- Purpose: URL-safe Base64 token serialization and deserialization for opaque keyset pagination.
-- Dependencies: 001_base

-- ============================================================================
-- 1. CURSOR DECODER
-- ============================================================================

-- Decode and validate a URL-safe Base64 pagination cursor.
create or replace function multitenancy._cursor_decode(
  p_tenant_id uuid,
  p_section   text,
  p_cursor    text
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_payload  jsonb;
  v_after_id uuid;
begin
  if p_cursor is null then
    return null;
  end if;

  begin
    v_payload := convert_from(
      decode(
        replace(replace(p_cursor, '-', '+'), '_', '/') || repeat('=', (4 - length(p_cursor) % 4) % 4),
        'base64'
      ),
      'utf8'
    )::jsonb;

    if (v_payload->>'v') is distinct from '1'
       or (v_payload->>'tenant_id') is distinct from p_tenant_id::text
       or (v_payload->>'section') is distinct from p_section
       or jsonb_typeof(v_payload->'after') is distinct from 'object' then
      raise exception 'invalid cursor payload structure';
    end if;

    v_after_id := (v_payload#>>'{after,id}')::uuid;
    if v_after_id is null then
      raise exception 'missing cursor id';
    end if;

    if p_section in ('members', 'invitations', 'audit') and (v_payload#>>'{after,created_at}')::timestamptz is null then
      raise exception 'missing cursor timestamp';
    elsif p_section = 'scopes' and (v_payload#>>'{after,kind}' is null or v_payload#>>'{after,key}' is null) then
      raise exception 'missing cursor scope attributes';
    elsif p_section in ('permissions', 'roles') and (v_payload#>>'{after,key}' is null) then
      raise exception 'missing cursor key';
    end if;

    return v_payload->'after';
  exception when others then
    raise exception 'INVALID_CURSOR' using errcode = '22023';
  end;
end;
$$;

revoke all on function multitenancy._cursor_decode(uuid, text, text) from public, anon, authenticated;
grant execute on function multitenancy._cursor_decode(uuid, text, text) to service_role;


-- ============================================================================
-- 2. CURSOR ENCODER
-- ============================================================================

-- Encode a pagination continuation state into a URL-safe Base64 token.
create or replace function multitenancy._cursor_encode(
  p_tenant_id uuid,
  p_section   text,
  p_after     jsonb
)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select rtrim(
    replace(
      replace(
        replace(
          encode(
            convert_to(
              jsonb_build_object(
                'v',         1,
                'tenant_id', p_tenant_id,
                'section',   p_section,
                'after',     p_after
              )::text,
              'utf8'
            ),
            'base64'
          ),
          E'\n', ''
        ),
        '+', '-'
      ),
      '/', '_'
    ),
    '='
  );
$$;

revoke all on function multitenancy._cursor_encode(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._cursor_encode(uuid, text, jsonb) to service_role;
-- END 008_rpc_cursor.sql

-- BEGIN 009_rpc_context.sql
-- 009_rpc_context.sql
-- supabase-multitenancy v0.3.0 — Context discovery & keyset cursor pagination
-- Purpose: Keyset-paginated metadata inspection and client context queries.
-- Dependencies: 006_authorize, 008_rpc_cursor

-- ============================================================================
-- 1. KEYSET PAGINATED CONTEXT
-- ============================================================================

create or replace function multitenancy.context_page(
  p_tenant_id uuid,
  p_section   text,
  p_cursor    text default null,
  p_limit     int default 50
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid              uuid := auth.uid();
  v_after            jsonb;
  v_items            jsonb;
  v_next             text;
  v_last             jsonb;
  v_after_key        text;
  v_after_kind       text;
  v_after_id         uuid;
  v_after_created_at timestamptz;
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  if not exists (
    select 1 from multitenancy.memberships
    where tenant_id = p_tenant_id and user_id = v_uid and status = 'active'
  ) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  p_limit := least(greatest(coalesce(p_limit, 50), 1), 100);

  if p_section not in ('permissions', 'roles', 'scopes', 'members', 'invitations', 'audit') then
    raise exception 'INVALID_INPUT: unknown section %', p_section using errcode = '22P02';
  end if;

  if p_section in ('members', 'invitations')
     and not multitenancy.has_access(p_tenant_id, 'multitenancy.members.read', null, 'own') then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  if p_section = 'audit'
     and not multitenancy.has_access(p_tenant_id, 'multitenancy.audit.read', null, 'own') then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  v_after := multitenancy._cursor_decode(p_tenant_id, p_section, p_cursor);
  if v_after is not null then
    v_after_key        := v_after->>'key';
    v_after_kind       := v_after->>'kind';
    v_after_id         := (v_after->>'id')::uuid;
    v_after_created_at := (v_after->>'created_at')::timestamptz;
  end if;

  case p_section
    when 'permissions' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select id, key, origin, is_deprecated
        from multitenancy.permissions
        where p_cursor is null or (key, id) > (v_after_key, v_after_id)
        order by key, id
        limit p_limit + 1
      ) x;

    when 'roles' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select
          rl.id,
          rl.key,
          rl.name,
          rl.description,
          rl.tenant_id,
          (
            select coalesce(
              jsonb_agg(
                jsonb_build_object('key', perm.key, 'access_level', rp.access_level)
                order by perm.key
              ),
              '[]'::jsonb
            )
            from multitenancy.role_permissions rp
            join multitenancy.permissions perm on perm.id = rp.permission_id
            where rp.role_id = rl.id
          ) as permissions
        from multitenancy.roles rl
        where (rl.tenant_id is null or rl.tenant_id = p_tenant_id)
          and (p_cursor is null or (rl.key, rl.id) > (v_after_key, v_after_id))
        order by rl.key, rl.id
        limit p_limit + 1
      ) x;

    when 'scopes' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.kind, x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select id, kind, key, name
        from multitenancy.scopes
        where tenant_id = p_tenant_id
          and (p_cursor is null or (kind, key, id) > (v_after_kind, v_after_key, v_after_id))
        order by kind, key, id
        limit p_limit + 1
      ) x;

    when 'members' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at, x.id), '[]'::jsonb)
      into v_items
      from (
        select
          mem.id,
          mem.user_id,
          mem.status,
          prof.display_name,
          mem.created_at,
          (
            select coalesce(
              jsonb_agg(jsonb_build_object('role_id', ra.role_id, 'scope_id', ra.scope_id)),
              '[]'::jsonb
            )
            from multitenancy.role_assignments ra
            where ra.membership_id = mem.id
          ) as grants
        from multitenancy.memberships mem
        left join multitenancy.profiles prof on prof.user_id = mem.user_id
        where mem.tenant_id = p_tenant_id
          and (p_cursor is null or (mem.created_at, mem.id) > (v_after_created_at, v_after_id))
        order by mem.created_at, mem.id
        limit p_limit + 1
      ) x;

    when 'invitations' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at desc, x.id desc), '[]'::jsonb)
      into v_items
      from (
        select id, email, email_normalized, expires_at, revoked_at, accepted_at, created_at
        from multitenancy.invitations
        where tenant_id = p_tenant_id
          and (p_cursor is null or (created_at, id) < (v_after_created_at, v_after_id))
        order by created_at desc, id desc
        limit p_limit + 1
      ) x;

    when 'audit' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at desc, x.id desc), '[]'::jsonb)
      into v_items
      from (
        select id, actor_user_id, command, entity_type, entity_id, payload, created_at
        from multitenancy.audit_events
        where tenant_id = p_tenant_id
          and (p_cursor is null or (created_at, id) < (v_after_created_at, v_after_id))
        order by created_at desc, id desc
        limit p_limit + 1
      ) x;
  end case;

  if jsonb_array_length(v_items) > p_limit then
    v_items := (
      select coalesce(jsonb_agg(value order by ordinality), '[]'::jsonb)
      from jsonb_array_elements(v_items) with ordinality
      where ordinality <= p_limit
    );
    v_last := v_items->(p_limit - 1);
    v_next := multitenancy._cursor_encode(
      p_tenant_id,
      p_section,
      case
        when p_section = 'scopes' then
          jsonb_build_object('kind', v_last->>'kind', 'key', v_last->>'key', 'id', v_last->>'id')
        when p_section in ('permissions', 'roles') then
          jsonb_build_object('key', v_last->>'key', 'id', v_last->>'id')
        else
          jsonb_build_object('created_at', v_last->>'created_at', 'id', v_last->>'id')
      end
    );
  else
    v_next := null;
  end if;

  return jsonb_build_object(
    'api_version', 1,
    'data', jsonb_build_object(
      'items',      v_items,
      'nextCursor', v_next
    )
  );
end;
$$;

revoke all on function multitenancy.context_page(uuid, text, text, int) from public, anon;
grant execute on function multitenancy.context_page(uuid, text, text, int) to authenticated, service_role;


-- ============================================================================
-- 2. CONTEXT HELPER (SINGLE-PAGE OR SELF)
-- ============================================================================

drop function if exists multitenancy.context(uuid, text, text, int);
create or replace function multitenancy.context(
  p_tenant_id uuid,
  p_section   text,
  p_limit     int default 50
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid    uuid := auth.uid();
  v_result jsonb;
begin
  if p_section <> 'self' then
    return jsonb_build_object(
      'api_version', 1,
      'data', (multitenancy.context_page(p_tenant_id, p_section, null, p_limit))->'data'->'items'
    );
  end if;

  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
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

  select jsonb_build_object(
    'tenant', (
      select row_to_json(t)
      from (
        select id, slug, name, owner_user_id, is_active
        from multitenancy.tenants
        where id = p_tenant_id
      ) t
    ),
    'membership', (
      select row_to_json(m)
      from (
        select id, status
        from multitenancy.memberships
        where tenant_id = p_tenant_id
          and user_id   = v_uid
      ) m
    ),
    'is_owner', (
      select (owner_user_id = v_uid)
      from multitenancy.tenants
      where id = p_tenant_id
    )
  ) into v_result;

  return jsonb_build_object(
    'api_version', 1,
    'data',        v_result
  );
end;
$$;

revoke all on function multitenancy.context(uuid, text, int) from public, anon;
grant execute on function multitenancy.context(uuid, text, int) to authenticated, service_role;
-- END 009_rpc_context.sql

-- BEGIN 010_rpc_invitations.sql
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
-- END 010_rpc_invitations.sql

-- BEGIN 011_admin_tenant.sql
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
-- END 011_admin_tenant.sql

-- BEGIN 012_admin_scope.sql
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
-- END 012_admin_scope.sql

-- BEGIN 013_admin_member.sql
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
-- END 013_admin_member.sql

-- BEGIN 014_admin_invitation.sql
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
-- END 014_admin_invitation.sql

-- BEGIN 015_admin_router.sql
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
-- END 015_admin_router.sql

-- BEGIN 016_api_boundary.sql
-- 016_api_boundary.sql
-- supabase-multitenancy v0.3.0 — API Boundary, schema lockdown & wrappers
-- Purpose: Expose public `api` routines and strictly lock down internal `multitenancy` schema.
-- Dependencies: 001_base through 015_admin_router

-- ============================================================================
-- 1. SCHEMA LOCKDOWN
-- ============================================================================

create schema if not exists api;

-- Revoke all direct client access to private package tables and routines
revoke all on schema multitenancy from public, anon, authenticated;
revoke all on all tables in schema multitenancy from public, anon, authenticated;
revoke all on all sequences in schema multitenancy from public, anon, authenticated;
revoke all on all functions in schema multitenancy from public, anon, authenticated;

-- Grant schema usage
grant usage on schema multitenancy to service_role;
grant usage on schema api to anon, authenticated;


-- ============================================================================
-- 2. PUBLIC API WRAPPERS & RLS HELPERS
-- ============================================================================

-- RLS helper: access level ('none', 'own', 'all')
create or replace function api.access_level(
  p_tenant_id      uuid,
  p_permission_key text,
  p_scope_ids      uuid[] default null
)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.access_level($1, $2, $3);
$$;

-- RLS helper: boolean check for required access level ('own' or 'all')
create or replace function api.has_access(
  p_tenant_id      uuid,
  p_permission_key text,
  p_scope_ids      uuid[],
  p_required_access text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.has_access($1, $2, $3, $4);
$$;

-- RLS helper: backward-compatible boolean check for 'own' or 'all'
create or replace function api.authorize(
  p_tenant_id      uuid,
  p_permission_key text,
  p_scope_ids      uuid[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.authorize($1, $2, $3);
$$;

-- Table trigger: enforce tenant and scope foreign key immutability
create or replace function api.enforce_protected_keys_immutable()
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
    if v_old->tg_argv[v_index] is distinct from v_new->tg_argv[v_index] then
      raise exception 'PROTECTED_KEY_IMMUTABLE: %', tg_argv[v_index] using errcode = '42501';
    end if;
  end loop;
  return new;
end;
$$;

-- Browser RPC: self-service tenant creation
create or replace function api.create_tenant(
  p_slug text,
  p_name text
)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select multitenancy.create_tenant($1, $2);
$$;

-- Browser RPC: UI permission check helper
create or replace function api.can(
  p_tenant_id  uuid,
  p_permission text,
  p_scope_ids  uuid[]
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.can($1, $2, $3);
$$;

-- Browser RPC: unified administrative command dispatcher
create or replace function api.admin(
  p_tenant_id uuid,
  p_command   text,
  p_payload   jsonb
)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select multitenancy.admin($1, $2, $3);
$$;

-- Browser RPC: invitation preview (public/anon + authenticated)
create or replace function api.invitation_preview(
  p_token text
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.invitation_preview($1);
$$;

-- Browser RPC: invitation acceptance
create or replace function api.accept_invitation(
  p_token text
)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select multitenancy.accept_invitation($1);
$$;

-- Browser RPC: keyset-paginated metadata inspection
create or replace function api.context_page(
  p_tenant_id uuid,
  p_section   text,
  p_cursor    text default null,
  p_limit     int default 50
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.context_page($1, $2, $3, $4);
$$;

-- Browser RPC: single-page / self context helper
drop function if exists api.context(uuid, text, text, int);
create or replace function api.context(
  p_tenant_id uuid,
  p_section   text,
  p_limit     int default 50
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select multitenancy.context($1, $2, $3);
$$;


-- ============================================================================
-- 3. API PERMISSIONS
-- ============================================================================

revoke all on all functions in schema api from public, anon, authenticated;

grant execute on function api.invitation_preview(text) to anon, authenticated;

grant execute on function
  api.create_tenant(text, text),
  api.can(uuid, text, uuid[]),
  api.admin(uuid, text, jsonb),
  api.accept_invitation(text),
  api.context_page(uuid, text, text, int),
  api.context(uuid, text, int),
  api.access_level(uuid, text, uuid[]),
  api.has_access(uuid, text, uuid[], text),
  api.authorize(uuid, text, uuid[]),
  api.enforce_protected_keys_immutable()
to authenticated;


-- ============================================================================
-- 4. PACKAGE VERSION
-- ============================================================================

update multitenancy.package_meta
set version = '0.3.0',
    installed_at = now()
where id = 1;
-- END 016_api_boundary.sql
