-- Copy this file into a consumer-owned Supabase migration and edit the values.
-- Permission keys are DBA-managed migration data.

insert into multitenancy.permissions (key, origin, description) values
  ('documents.read', 'application', 'Read documents'),
  ('documents.create', 'application', 'Create documents'),
  ('documents.update', 'application', 'Update documents'),
  ('documents.delete', 'application', 'Delete documents')
on conflict (key) do update
set description = excluded.description,
    is_deprecated = false;

-- Deprecate removed keys explicitly. Do not delete keys that may be referenced
-- by historical audit data or a role profile.
-- update multitenancy.permissions
-- set is_deprecated = true
-- where key = 'documents.legacy_action';
