-- 002_identities.sql
-- supabase-tenant-rbac v0.2.0 — Identities: profiles, tenants, scopes, memberships
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
  unique(tenant_id, user_id)
);
create index if not exists idx_memberships_tenant on multitenancy.memberships(tenant_id);
create index if not exists idx_memberships_user on multitenancy.memberships(user_id);
create index if not exists idx_memberships_tenant_user_status on multitenancy.memberships(tenant_id, user_id, status);
drop trigger if exists trg_memberships_touch on multitenancy.memberships;
create trigger trg_memberships_touch before update on multitenancy.memberships
  for each row execute function multitenancy.touch_updated_at();
