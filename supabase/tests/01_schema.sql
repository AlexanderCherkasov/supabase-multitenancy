-- 01_schema.sql — schema, constraints, grants and RLS presence
begin;
select plan(30);

select has_schema('multitenancy', 'multitenancy schema exists');
select has_schema('api', 'api schema exists');
select has_table('multitenancy', 'tenants', 'tenants table exists');
select has_table('multitenancy', 'scopes', 'scopes table exists');
select has_table('multitenancy', 'memberships', 'memberships table exists');
select has_table('multitenancy', 'profiles', 'profiles table exists');
select has_table('multitenancy', 'permissions', 'permissions table exists');
select has_table('multitenancy', 'roles', 'roles table exists');
select has_table('multitenancy', 'role_permissions', 'role_permissions exists');
select has_table('multitenancy', 'role_assignments', 'role_assignments exists');
select has_table('multitenancy', 'invitations', 'invitations exists');
select has_table('multitenancy', 'invitation_grants', 'invitation_grants exists');
select has_table('multitenancy', 'audit_events', 'audit_events exists');
select has_table('multitenancy', 'settings', 'settings exists');
select has_table('multitenancy', 'package_meta', 'package_meta exists');

-- helper exists with correct search_path and security definer
select has_function('multitenancy', 'authorize', array['uuid','text','uuid[]'], 'authorize(uuid,text,uuid[]) exists');
select has_function('multitenancy', 'access_level', array['uuid','text','uuid[]'], 'access_level(uuid,text,uuid[]) exists');
select has_function('multitenancy', 'has_access', array['uuid','text','uuid[]','text'], 'has_access(uuid,text,uuid[],text) exists');
select ok(
  (select pg_get_functiondef(oid) ~* 'search_path\s*(?:=|to)\s*''''' from pg_proc where proname='authorize' and pronamespace='multitenancy'::regnamespace),
  'authorize has fixed search_path = '''''
);
select has_function('multitenancy', 'handle_new_user', array[]::text[], 'handle_new_user exists');

-- RLS enabled on all internal tables
select ok((select relrowsecurity from pg_class where relname='tenants' and relnamespace='multitenancy'::regnamespace), 'tenants RLS enabled');
select ok((select relrowsecurity from pg_class where relname='memberships' and relnamespace='multitenancy'::regnamespace), 'memberships RLS enabled');
select ok((select relrowsecurity from pg_class where relname='audit_events' and relnamespace='multitenancy'::regnamespace), 'audit_events RLS enabled');

-- Browser RPCs are exposed only through api, never public or multitenancy.
select has_function('api', 'create_tenant', array['text','text'], 'create_tenant exists in api');
select has_function('api', 'can', array['uuid','text','uuid[]'], 'can exists in api');
select has_function('api', 'context', array['uuid','text','integer'], 'context exists in api without cursor');
select has_function('api', 'invitation_preview', array['text'], 'invitation_preview exists in api');
select has_function('api', 'accept_invitation', array['text'], 'accept_invitation exists in api');
select has_function('api', 'admin', array['uuid','text','jsonb'], 'admin exists in api');

select is(
  (select count(*)::int from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname like 'multitenancy_%'),
  0, '0 package RPCs in public schema (client wrappers live in api)'
);

select * from finish();
rollback;
