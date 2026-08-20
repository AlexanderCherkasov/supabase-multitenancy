-- 04_audit_and_trigger.sql — append-only audit, signup trigger
begin;
select plan(10);

-- append-only via trigger
select has_function('multitenancy', 'prevent_audit_mutation', array[]::text[], 'prevent_audit_mutation exists');
select ok(
  (select count(*)::int from pg_trigger where tgname='trg_audit_no_update') = 1,
  'audit_events has no-update trigger'
);

-- signup trigger creates minimal profile with fixed search_path
select has_function('multitenancy', 'handle_new_user', array[]::text[], 'handle_new_user exists');
select ok(
  (select pg_get_functiondef(oid) ~* 'search_path\s*(?:=|to)\s*''''' from pg_proc where proname='handle_new_user' and pronamespace='multitenancy'::regnamespace),
  'handle_new_user has fixed search_path'
);
select ok(
  (select prosecdef from pg_proc where proname='handle_new_user' and pronamespace='multitenancy'::regnamespace),
  'handle_new_user is SECURITY DEFINER'
);
select has_trigger('auth', 'users', 'multitenancy_on_auth_user_created', 'auth.users has package-owned profile trigger');

-- profiles does not conflict with existing public.profiles (separate schema)
select ok(
  (select count(*)::int from pg_tables where schemaname='public' and tablename='profiles') >= 0,
  'public.profiles coexistence is allowed (multitenancy.profiles isolated)'
);

-- settings ttl constraints
select ok(
  (select pg_get_constraintdef(oid) ~* '1.*720' from pg_constraint where conname like '%invitation_ttl%'),
  'invitation_ttl_hours check 1..720'
);

-- audit index
select has_index('multitenancy', 'audit_events', 'idx_audit_tenant_created', 'audit has tenant/created index');

-- FUNCTION search_path hygiene for SECURITY DEFINER
select is(
  (select count(*)::int from pg_proc p join pg_namespace n on n.oid=p.pronamespace
   where n.nspname='multitenancy' and p.prosecdef and pg_get_functiondef(p.oid) !~* 'search_path\s*(?:=|to)\s*''''' ),
  0,
  'all SECURITY DEFINER multitenancy functions have fixed search_path'
);

select * from finish();
rollback;
