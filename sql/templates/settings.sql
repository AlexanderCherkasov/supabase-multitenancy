-- Copy into a consumer migration to override package defaults.
update multitenancy.settings
set self_service_tenant_creation = false,
    invitation_ttl_hours = 72
where id = 1;
