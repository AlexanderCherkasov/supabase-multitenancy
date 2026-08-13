-- Example permission catalog.
insert into multitenancy.permissions (key, description, origin) values
  ('documents.read', 'Read documents', 'application'),
  ('documents.create', 'Create documents', 'application'),
  ('documents.update', 'Update documents', 'application'),
  ('documents.delete', 'Delete documents', 'application')
on conflict (key) do update
set description = excluded.description, is_deprecated = false;

-- DBA-managed role profiles. Apply only as a reviewed database migration.
-- Replace the tenant UUID before applying.
with inserted as (
  insert into multitenancy.roles (tenant_id, key, name) values
    ('00000000-0000-0000-0000-000000000001', 'editor', 'Editor'),
    ('00000000-0000-0000-0000-000000000001', 'viewer', 'Viewer')
  on conflict (tenant_id, key) do update set name = excluded.name
  returning id, key
)
insert into multitenancy.role_permissions (role_id, permission_id, access_level)
select r.id, p.id,
  case
    when r.key = 'viewer' then 'all'
    when p.key in ('documents.update', 'documents.delete') then 'own'
    else 'all'
  end
from inserted r
join multitenancy.permissions p
  on p.key in ('documents.read', 'documents.create', 'documents.update', 'documents.delete')
on conflict (role_id, permission_id) do update
set access_level = excluded.access_level;
