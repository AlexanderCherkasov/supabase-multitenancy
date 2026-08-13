-- Step 1: Application Tables (Documents and Tenant-Managed Collaborators)

-- 1. Main Documents Table
create table if not exists public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid null,
  author_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  content text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint fk_documents_scope foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

-- 2. Tenant-Managed Collaborators Table
-- Allows document authors or managers to share access to specific documents with other tenant members.
create table if not exists public.document_collaborators (
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  document_id uuid not null references public.documents(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  permission_level text not null default 'edit' check (permission_level in ('view', 'edit')),
  created_at timestamptz not null default now(),

  primary key (document_id, user_id)
);

-- Fast lookup indexes
create index if not exists idx_doc_collab_user on public.document_collaborators(user_id, document_id);
create index if not exists idx_doc_collab_tenant on public.document_collaborators(tenant_id);

-- Enforce key immutability on documents
drop trigger if exists trg_documents_protect on public.documents;
create trigger trg_documents_protect
  before update on public.documents
  for each row execute function multitenancy.enforce_protected_keys_immutable('project_id');

-- Enable Row-Level Security on both tables
alter table public.documents enable row level security;
alter table public.document_collaborators enable row level security;
