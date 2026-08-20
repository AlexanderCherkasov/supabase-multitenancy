-- Copy this file into a consumer-owned DBA migration.
-- Global roles are the normal case. No public RPC can perform these writes.

with role_row as (
  insert into multitenancy.roles (key, name, description)
  values (
    'editor',
    'Editor',
    'Can read all documents and update owned documents'
  )
  on conflict (key) do update
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

-- Rare exception: a DBA may create a role usable only in one tenant. Its key
-- remains globally unique, so prefix it rather than trying to override editor.
-- insert into multitenancy.roles (tenant_id, key, name, description)
-- values ('<tenant-uuid>', 'acme_compliance_reviewer', 'Compliance reviewer',
--         'DBA-owned role restricted to the Acme tenant');
