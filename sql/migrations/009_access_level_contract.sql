-- 009_access_level_contract.sql
-- supabase-multitenancy v0.2.0 — Finalize the safe row-access contract
--
-- Role data may select only `own` or `all`. Row ownership columns and custom
-- predicates belong to application migrations and generated RLS policies.
-- They are never resolved dynamically inside a SECURITY DEFINER function.

drop function if exists multitenancy.authorize_row(uuid, text, uuid[], jsonb);
drop function if exists multitenancy.validate_role_permission_check();

alter table multitenancy.role_permissions
  drop column if exists check_function,
  drop column if exists owner_column,
  drop column if exists access_mode;

update multitenancy.package_meta
set version = '0.2.0', installed_at = now()
where id = 1;
