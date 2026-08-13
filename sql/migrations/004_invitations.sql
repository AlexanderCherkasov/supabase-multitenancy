-- 004_invitations.sql
-- supabase-tenant-rbac v0.2.0 — Invitations with one-time tokens
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
