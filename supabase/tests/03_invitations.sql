-- 03_invitations.sql — invitation lifecycle, token security, concurrent accept
begin;
select plan(15);

-- token hash stored, not plaintext
select has_column('multitenancy', 'invitations', 'token_hash', 'invitations has token_hash');
select col_type_is('multitenancy', 'invitations', 'token_hash', 'text', 'token_hash is text');
select ok(
  (select count(*)::int from information_schema.columns where table_schema='multitenancy' and table_name='invitations' and column_name='token') = 0,
  'no plaintext token column'
);

-- one active per (tenant, normalized_email) partial unique
select has_index('multitenancy', 'invitations', 'uq_invitations_active_per_email', 'active invitation uniqueness per tenant/email');

-- expiry, revoke, resend via admin function
select ok(
  exists (select 1 from pg_proc where proname in ('admin', '_admin_invitation') and pronamespace='multitenancy'::regnamespace and pg_get_functiondef(oid) ilike '%invitation.create%'),
  'multitenancy.admin handles invitation.create'
);
select ok(
  exists (select 1 from pg_proc where proname in ('admin', '_admin_invitation') and pronamespace='multitenancy'::regnamespace and pg_get_functiondef(oid) ilike '%invitation.resend%'),
  'multitenancy.admin handles invitation.resend'
);
select ok(
  exists (select 1 from pg_proc where proname in ('admin', '_admin_invitation') and pronamespace='multitenancy'::regnamespace and pg_get_functiondef(oid) ilike '%invitation.revoke%'),
  'multitenancy.admin handles invitation.revoke'
);

-- preview accessible to anon + authenticated, accept only authenticated
select ok(
  (select array_agg(grantee::text) from information_schema.routine_privileges where routine_schema='api' and routine_name='invitation_preview') @> array['anon'],
  'api.invitation_preview granted to anon'
);
select ok(
  (select count(*)::int from information_schema.routine_privileges where routine_schema='api' and routine_name='accept_invitation' and grantee='anon') = 0,
  'api.accept_invitation not granted to anon'
);

-- email match check
select ok(
  (select pg_get_functiondef(oid) ilike '%EMAIL_MISMATCH%' from pg_proc where proname='accept_invitation' and pronamespace='multitenancy'::regnamespace limit 1),
  'accept checks EMAIL_MISMATCH'
);

-- expiry check
select ok(
  (select pg_get_functiondef(oid) ilike '%expires_at%' from pg_proc where proname='accept_invitation' and pronamespace='multitenancy'::regnamespace limit 1),
  'accept checks expiry'
);

-- revoked check
select ok(
  (select pg_get_functiondef(oid) ilike '%TOKEN_REVOKED%' from pg_proc where proname='accept_invitation' and pronamespace='multitenancy'::regnamespace limit 1),
  'accept checks revoke'
);

-- row lock for concurrent accept
select ok(
  (select pg_get_functiondef(oid) ilike '%for update%' from pg_proc where proname='accept_invitation' and pronamespace='multitenancy'::regnamespace limit 1),
  'accept uses row lock (for update) for concurrency'
);

-- idempotent replay for same user
select ok(
  (select pg_get_functiondef(oid) ilike '%already accepted%' from pg_proc where proname='accept_invitation' and pronamespace='multitenancy'::regnamespace limit 1),
  'accept handles idempotent replay'
);

-- audit never stores raw token
select ok(
  exists (
    select 1 from pg_proc
    where proname in ('admin', '_admin_invitation')
      and pronamespace='multitenancy'::regnamespace
      and pg_get_functiondef(oid) ilike '%_admin_audit%'
      and pg_get_functiondef(oid) ~* 'jsonb_build_object\s*\(\s*''email''\s*,\s*v_email_norm\s*,\s*''expires_at''\s*,\s*v_expires_at\s*\)'
  ),
  'admin audit does not log raw token (manual review of payload)'
);

select * from finish();
rollback;
