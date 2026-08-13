# supabase-multitenancy

Python client for the SQL-first `supabase-multitenancy` package.

```python
from supabase import create_client
from supabase_multitenancy import MultitenancyClient

supabase = create_client(url, publishable_key)
mt = MultitenancyClient(supabase)

tenant = mt.create_tenant(slug="acme", name="Acme")
roles = mt.roles.list(tenant["tenant_id"])
allowed = mt.can(tenant["tenant_id"], "documents.read")
```

The wrapped Supabase client must carry the current user's session. Never initialize a browser or untrusted client with a service-role/secret key. Roles are read-only in this SDK because only DBA migrations may define them.
