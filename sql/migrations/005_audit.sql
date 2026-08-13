-- 005_audit.sql
-- supabase-tenant-rbac v0.2.0 — Audit log (append-only)
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
