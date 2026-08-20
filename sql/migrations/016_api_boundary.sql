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
