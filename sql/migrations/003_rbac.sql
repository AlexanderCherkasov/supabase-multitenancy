-- 003_rbac.sql
-- supabase-multitenancy v0.2.0 — RBAC: permissions, roles, access levels, assignments
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
-- roles — tenant-local but DBA-managed; no public RPC mutates this table
-- ---------------------------------------------------------------------------
create table if not exists multitenancy.roles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  key text not null check (key ~ '^[a-z][a-z0-9_]{1,39}$'),
  name text not null check (char_length(name) between 1 and 120),
  description text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, key)
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
  membership_id uuid not null references multitenancy.memberships(id) on delete cascade,
  role_id uuid not null references multitenancy.roles(id) on delete cascade,
  scope_id uuid, -- nullable = tenant-wide
  created_at timestamptz not null default now(),
  unique(membership_id, role_id, scope_id)
);
create index if not exists idx_role_assignments_membership on multitenancy.role_assignments(membership_id);
create index if not exists idx_role_assignments_role on multitenancy.role_assignments(role_id);
create index if not exists idx_role_assignments_scope on multitenancy.role_assignments(scope_id);
create unique index if not exists uq_role_assignments_tenant_wide
  on multitenancy.role_assignments(membership_id, role_id) where scope_id is null;

-- Enforce that role, membership, and scope all belong to the same tenant
create or replace function multitenancy.enforce_assignment_scope_tenant()
returns trigger language plpgsql as $$
declare v_tenant uuid; v_scope_tenant uuid;
begin
  select tenant_id into v_tenant from multitenancy.memberships where id = new.membership_id;
  select tenant_id into v_scope_tenant from multitenancy.roles where id = new.role_id;
  if v_tenant is null or v_scope_tenant is null or v_tenant <> v_scope_tenant then
    raise exception 'role and membership must belong to same tenant' using errcode='23503';
  end if;
  if new.scope_id is not null then
    select tenant_id into v_scope_tenant from multitenancy.scopes where id = new.scope_id;
    if v_scope_tenant is null or v_scope_tenant <> v_tenant then
      raise exception 'scope must belong to same tenant as membership' using errcode='23503';
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists trg_assignments_scope_check on multitenancy.role_assignments;
create trigger trg_assignments_scope_check
  before insert or update on multitenancy.role_assignments
  for each row execute function multitenancy.enforce_assignment_scope_tenant();
