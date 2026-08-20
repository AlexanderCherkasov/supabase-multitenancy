-- 02_authorization.sql — structural authorization and anti-escalation checks
begin;
select plan(16);

select ok(
  (select pg_get_functiondef(oid) ilike '%owner_user_id%' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'access_level contains owner bypass'
);
select ok(
  (select pg_get_functiondef(oid) ~* 'key\s*=\s*p_permission\s+and\s+not\s+(?:\w+\.)?is_deprecated' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'deprecated permissions deny'
);
select ok(
  (select pg_get_functiondef(oid) ~* 'user_id\s*=\s*v_uid\s+and\s+(?:\w+\.)?status\s*=\s*''active''' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'only active memberships authorize'
);
select ok(
  (select pg_get_functiondef(oid) ~* 'cardinality\s*\(\s*p_scope_ids\s*\)\s*=\s*0' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'empty scopes require tenant-wide assignment'
);
select ok(
  (select pg_get_functiondef(oid) ~* 'least\s*\(\s*v_effective(?:_rank)?\s*,\s*v_rank\s*\)' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'multi-scope access uses the weakest covered level'
);
select ok(
  (select pg_get_functiondef(oid) ~* 'ra\.scope_id\s+is\s+null\s+or\s+ra\.scope_id\s*=\s*v_scope_id' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'tenant-wide assignments inherit into scopes'
);
select ok(
  (select pg_get_functiondef(oid) ilike '%rp.access_level%' from pg_proc where proname='access_level' and pronamespace='multitenancy'::regnamespace),
  'resolver reads own/all levels'
);
select ok(
  (select pg_get_functiondef(oid) ilike '%p_required_level%' from pg_proc where proname='has_access' and pronamespace='multitenancy'::regnamespace),
  'has_access compares a required level'
);
select ok(
  exists (select 1 from pg_proc where proname in ('admin', '_admin_member') and pronamespace='multitenancy'::regnamespace and pg_get_functiondef(oid) ilike '%rp.access_level%'),
  'admin escalation guard compares access levels'
);
select ok(
  exists (select 1 from pg_proc where proname in ('admin', '_admin_member', '_admin_invitation') and pronamespace='multitenancy'::regnamespace and pg_get_functiondef(oid) ilike '%ROLE_ESCALATION%'),
  'admin reports role escalation'
);
select ok(
  (select pg_get_functiondef(oid) ilike '%roles and role permissions are DBA-managed%' from pg_proc where proname='admin' and pronamespace='multitenancy'::regnamespace),
  'admin rejects every role mutation command'
);
select is(
  (select count(*)::int from information_schema.role_table_grants
   where table_schema='multitenancy' and table_name in ('roles','role_permissions')
     and grantee in ('anon','authenticated','service_role')),
  0,
  'client and service roles have no role-catalog table privileges'
);
select ok(
  not exists (
    select 1 from pg_proc
    where proname='authorize_row' and pronamespace='multitenancy'::regnamespace
  ),
  'legacy row-dispatch helper is absent'
);
select has_index('multitenancy', 'scopes', 'uq_scopes_tenant_id', 'scopes support composite tenant/scope foreign keys');
select has_index('multitenancy', 'memberships', 'idx_memberships_tenant_user_status', 'membership lookup is indexed');
select has_index('multitenancy', 'role_assignments', 'idx_role_assignments_membership', 'assignment lookup is indexed');

select * from finish();
rollback;
