-- 001_base.sql
-- supabase-tenant-rbac v0.2.0 — Base: extensions, schema, helpers, version
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
values (1, '0.2.0')
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
