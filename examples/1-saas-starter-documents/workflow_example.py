import os
from supabase import create_client
from supabase_multitenancy import MultitenancyClient

# 1. Initialize Supabase and Multitenancy Client
url = os.environ.get("SUPABASE_URL", "https://your-project.supabase.co")
anon_key = os.environ.get("SUPABASE_ANON_KEY", "your-anon-key")

supabase = create_client(url, anon_key)
mt = MultitenancyClient(supabase)

# 2. Sign in as Owner
supabase.auth.sign_in_with_password({"email": "owner@acme.com", "password": "password"})

# 3. Create Tenant
tenant = mt.create_tenant(slug="acme-corp", name="Acme Corporation")
tenant_id = tenant["tenant_id"]
print(f"Created Tenant: {tenant_id}")

# 4. Create Project Scope
scope = mt.scopes.create(tenant_id, kind="project", key="marketing", name="Marketing 2026")
scope_id = scope["scope_id"]
print(f"Created Project Scope: {scope_id}")

# 5. Fetch DBA Roles
roles = mt.roles.list(tenant_id)
editor_role = next(r for r in roles if r["key"] == "editor")

# 6. Invite Member to Scope
invite = mt.invitations.create(
    tenant_id,
    email="alice@acme.com",
    grants=[{"role_id": editor_role["id"], "scope_id": scope_id}],
)
print(f"Created Invite Token: {invite['token']}")

# 7. Check UI Permissions
can_create = mt.can(tenant_id, "documents.create", scope_ids=[scope_id])
can_delete = mt.can(tenant_id, "documents.delete", scope_ids=[scope_id])
print(f"Owner UI check -> Can Create: {can_create}, Can Delete: {can_delete}")
