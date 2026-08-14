-- ============================================================================
-- 01_permissions_and_roles.sql: Permissions & Role Catalog for Scoped Tasks
-- ============================================================================

-- 1. Declare abstract capabilities
insert into multitenancy.permissions (key, description) values
  ('tasks.read',   'Read tasks within covered tenant/scope'),
  ('tasks.create', 'Create tasks within covered tenant/scope'),
  ('tasks.update', 'Update tasks within covered tenant/scope'),
  ('tasks.delete', 'Delete tasks within covered tenant/scope')
on conflict (key) do update set description = excluded.description;

-- 2. Seed DBA-managed Roles with 'own' vs 'all' access levels
do $$
declare
  v_viewer_id uuid;
  v_editor_id uuid;
  v_manager_id uuid;
begin
  -- Role 1: Task Viewer (read own tasks)
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'task_viewer', 'Task Viewer', 'View own assigned tasks')
  on conflict (coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
  do update set name = excluded.name
  returning id into v_viewer_id;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_viewer_id, id, 'own'
  from multitenancy.permissions where key = 'tasks.read'
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

  -- Role 2: Task Editor (read, create, edit own tasks)
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'task_editor', 'Task Editor', 'Create and manage own tasks')
  on conflict (coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
  do update set name = excluded.name
  returning id into v_editor_id;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_editor_id, id, 'own'
  from multitenancy.permissions where key in ('tasks.read', 'tasks.create', 'tasks.update')
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

  -- Role 3: Task Manager (full control over all tasks in tenant/scope)
  insert into multitenancy.roles (tenant_id, key, name, description)
  values (null, 'task_manager', 'Task Manager', 'Manage all tasks and delete')
  on conflict (coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), key)
  do update set name = excluded.name
  returning id into v_manager_id;

  insert into multitenancy.role_permissions (role_id, permission_id, access_level)
  select v_manager_id, id, 'all'
  from multitenancy.permissions where key in ('tasks.read', 'tasks.create', 'tasks.update', 'tasks.delete')
  on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

end $$;
