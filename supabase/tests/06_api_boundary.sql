-- v0.3 API boundary and role catalog invariants.
select plan(12);

select has_schema('api', 'exposed api schema exists');
select ok(not exists (
  select 1 from information_schema.routines
  where routine_schema = 'public' and routine_name in
    ('create_tenant', 'context', 'context_page', 'admin', 'can')
), 'package RPCs are not placed in public');
select ok(exists (
  select 1 from information_schema.routines
  where routine_schema = 'api' and routine_name = 'create_tenant'
), 'create_tenant wrapper exists in api');
select ok(exists (
  select 1 from information_schema.routines
  where routine_schema = 'api' and routine_name = 'context_page'
), 'context_page wrapper exists in api');
select ok(exists (
  select 1 from information_schema.routines
  where routine_schema = 'api' and routine_name = 'access_level'
), 'access_level helper exists in api');
select ok(not exists (
  select 1 from information_schema.role_table_grants
  where table_schema = 'multitenancy'
    and grantee in ('anon', 'authenticated')
), 'client roles have no private table grants');
select ok(
  not has_schema_privilege('anon', 'multitenancy', 'USAGE')
  and not has_schema_privilege('authenticated', 'multitenancy', 'USAGE'),
  'client roles have no private schema usage'
);
select ok(exists (
  select 1 from information_schema.routine_privileges
  where routine_schema = 'api' and routine_name = 'create_tenant'
    and grantee = 'authenticated' and privilege_type = 'EXECUTE'
), 'authenticated can execute api.create_tenant');
select ok(not exists (
  select 1 from information_schema.routine_privileges
  where routine_schema = 'multitenancy' and routine_name = 'create_tenant'
    and grantee in ('anon', 'authenticated')
), 'private create_tenant is not executable by clients');
select ok(exists (
  select 1 from information_schema.columns
  where table_schema = 'multitenancy' and table_name = 'roles'
    and column_name = 'tenant_id' and is_nullable = 'YES'
), 'role tenant_id remains nullable for global roles');
select ok(exists (
  select 1 from information_schema.columns
  where table_schema = 'multitenancy' and table_name = 'role_assignments'
    and column_name = 'tenant_id'
), 'assignments carry explicit tenant_id');
select ok(exists (
  select 1 from pg_constraint c
  where c.conrelid = 'multitenancy.role_assignments'::regclass
    and c.contype = 'f'
    and pg_get_constraintdef(c.oid) ilike '%tenant_id%'
), 'assignment tenant invariant is enforced structurally');

select * from finish();
