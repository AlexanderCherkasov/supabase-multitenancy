-- Copy this file into a consumer-owned DBA migration.
-- Replace the UUID and role definitions. No public RPC can perform these writes.

with role_row as (
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (
    '00000000-0000-0000-0000-000000000001'::uuid,
    'editor',
    'Editor',
    'Can read all documents and update owned documents'
  )
  on conflict (tenant_id, key) do update
  set name = excluded.name,
      description = excluded.description
  returning id
)
insert into multitenancy.role_permissions (role_id, permission_id, access_level)
select role_row.id, permission.id, grants.access_level
from role_row
cross join (values
  ('documents.read', 'all'),
  ('documents.create', 'own'),
  ('documents.update', 'own')
) as grants(permission_key, access_level)
join multitenancy.permissions permission on permission.key = grants.permission_key
on conflict (role_id, permission_id) do update
set access_level = excluded.access_level;
