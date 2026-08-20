-- Step 1: Declare Permissions (DBA migration)
-- Permissions define abstract capabilities across your application.

insert into multitenancy.permissions (key, description) values
  ('documents.read',   'Read documents within tenant/scope'),
  ('documents.create', 'Create new documents within tenant/scope'),
  ('documents.update', 'Update existing documents (own or all)'),
  ('documents.delete', 'Delete documents (restricted to managers/owners)')
on conflict (key) do update set description = excluded.description;

-- Step 2: Define global role profiles with `own` vs `all` Access Levels
-- Role definitions are migration-owned. Tenant owners can assign roles to members,
-- but cannot create or elevate roles.

do $$
declare
  v_role_viewer uuid;
  v_role_editor uuid;
  v_role_manager uuid;
begin
  -- 1. VIEWER: Can read own documents
  insert into multitenancy.roles (key, name, description)
  values ('viewer', 'Document Viewer', 'Can view only own documents')
  on conflict (key)
  do update set name = excluded.name, description = excluded.description
  returning id into v_role_viewer;

  -- 2. EDITOR: Can read own, create, and update own documents
  insert into multitenancy.roles (key, name, description)
  values ('editor', 'Document Editor', 'Can create and edit own documents')
  on conflict (key)
  do update set name = excluded.name, description = excluded.description
  returning id into v_role_editor;

  -- 3. MANAGER: Can read all, create, update all, and delete all documents in tenant/scope
  insert into multitenancy.roles (key, name, description)
  values ('manager', 'Project Manager', 'Can manage all documents and delete')
  on conflict (key)
  do update set name = excluded.name, description = excluded.description
  returning id into v_role_manager;

  -- Map permissions to roles with explicit access levels ('own' or 'all')

  -- Viewer grants
  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_role_viewer, id, 'own'
  from multitenancy.permissions where key in ('documents.read')
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

  -- Editor grants
  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_role_editor, id, case key
    when 'documents.read'   then 'own'
    when 'documents.create' then 'own'
    when 'documents.update' then 'own'
  end
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update')
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

  -- Manager grants
  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_role_manager, id, 'all'
  from multitenancy.permissions where key in ('documents.read', 'documents.create', 'documents.update', 'documents.delete')
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

end $$;
