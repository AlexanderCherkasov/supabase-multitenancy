-- Consumer-owned application schema. The package never owns business tables.
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
  project_id uuid not null,
  author_id uuid not null references auth.users(id),
  title text not null,
  body text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (tenant_id, project_id)
    references multitenancy.scopes(tenant_id, id)
    on delete restrict
);

create index documents_tenant_project_idx on public.documents(tenant_id, project_id);
create index documents_author_idx on public.documents(author_id);

create table public.document_collaborators (
  tenant_id uuid not null,
  document_id uuid not null references public.documents(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  primary key (document_id, user_id)
);

-- Copy and adapt sql/templates/protect_table.sql. Its update trigger also makes
-- tenant_id and project_id immutable after insertion.
