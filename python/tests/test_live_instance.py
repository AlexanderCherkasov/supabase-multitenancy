import os
import random
import string
import unittest
import requests
from supabase_multitenancy import MultitenancyClient, MultitenancyError

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")


class PostgrestResponse:
    def __init__(self, data):
        self.data = data


class PostgrestRpcBuilder:
    def __init__(self, url: str, headers: dict, function_name: str, params: dict):
        self.url = f"{url}/rest/v1/rpc/{function_name}"
        self.headers = headers
        self.params = params

    def execute(self):
        resp = requests.post(self.url, headers=self.headers, json=self.params)
        if resp.status_code >= 400:
            try:
                err_json = resp.json()
                msg = err_json.get("message", resp.text)
                code = err_json.get("code", "")
            except Exception:
                msg = resp.text
                code = ""
            err = Exception(msg)
            err.message = msg
            err.code = code
            raise err
        return PostgrestResponse(resp.json())


class HttpSupabaseClient:
    def __init__(self, url: str, api_key: str, access_token: str = None):
        self.url = url
        self.api_key = api_key
        self.access_token = access_token or api_key

    def rpc(self, function_name: str, params: dict):
        headers = {
            "apikey": self.api_key,
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        return PostgrestRpcBuilder(self.url, headers, function_name, params)


def sign_up_and_in(email: str, password: str) -> str:
    # 1. Admin creates user in Supabase Auth via GoTrue Admin API
    admin_headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    create_url = f"{SUPABASE_URL}/auth/v1/admin/users"
    resp = requests.post(
        create_url,
        headers=admin_headers,
        json={"email": email, "password": password, "email_confirm": True},
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Failed to create user: {resp.text}")

    # 2. Sign in via password grant
    token_url = f"{SUPABASE_URL}/auth/v1/token?grant_type=password"
    sign_in_headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Content-Type": "application/json",
    }
    resp = requests.post(
        token_url,
        headers=sign_in_headers,
        json={"email": email, "password": password},
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Failed to sign in: {resp.text}")
    return resp.json()["access_token"]


@unittest.skipIf(
    not SUPABASE_URL or not SUPABASE_ANON_KEY or not SUPABASE_SERVICE_ROLE_KEY,
    "Supabase credentials not configured in environment (SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY)",
)
class LiveInstancePythonE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.run_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

        # 1. Create real test users in Supabase Auth
        cls.owner_email = f"py-owner-{cls.run_id}@example.com"
        cls.member_email = f"py-member-{cls.run_id}@example.com"
        cls.password = f"PyPass!{cls.run_id}99"

        cls.owner_token = sign_up_and_in(cls.owner_email, cls.password)
        cls.member_token = sign_up_and_in(cls.member_email, cls.password)

        cls.owner_http = HttpSupabaseClient(SUPABASE_URL, SUPABASE_ANON_KEY, cls.owner_token)
        cls.owner_mt = MultitenancyClient(cls.owner_http)

        cls.member_http = HttpSupabaseClient(SUPABASE_URL, SUPABASE_ANON_KEY, cls.member_token)
        cls.member_mt = MultitenancyClient(cls.member_http)

    def test_full_python_lifecycle(self):
        slug = f"py-org-{self.run_id}"

        # 1. Create tenant
        tenant = self.owner_mt.create_tenant(slug=slug, name="Python Test Org")
        tenant_id = tenant["tenant_id"]
        self.assertEqual(tenant["slug"], slug)

        # 2. Check context (self, permissions, audit)
        self_ctx = self.owner_mt.tenants.get_self(tenant_id)
        self.assertTrue(self_ctx["is_owner"])
        self.assertEqual(self_ctx["tenant"]["id"], tenant_id)

        perms = self.owner_mt.permissions.list(tenant_id)
        self.assertTrue(any(p["key"] == "documents.read" for p in perms))

        # 3. Scopes management
        scope = self.owner_mt.scopes.create(
            tenant_id,
            kind="project",
            key=f"api-{self.run_id}",
            name="API Service",
            metadata={"framework": "fastapi"},
        )
        scope_id = scope["id"]
        self.assertEqual(scope["name"], "API Service")

        scopes = self.owner_mt.scopes.list(tenant_id)
        self.assertEqual(len(scopes), 1)

        updated_scope = self.owner_mt.scopes.update(tenant_id, scope_id, name="API Service V2")
        self.assertEqual(updated_scope["name"], "API Service V2")

        # 4. Invitation lifecycle
        inv = self.owner_mt.invitations.create(tenant_id, email=self.member_email, grants=[])
        self.assertTrue(inv["token"])
        self.assertTrue(inv["invitation_id"])

        # Preview invitation using unauthenticated client
        anon_http = HttpSupabaseClient(SUPABASE_URL, SUPABASE_ANON_KEY)
        anon_mt = MultitenancyClient(anon_http)
        preview = anon_mt.invitations.preview(inv["token"])
        self.assertTrue(preview["valid"])
        self.assertEqual(preview["tenant_id"], tenant_id)
        self.assertIn("***", preview["email_masked"])

        # Member accepts invitation
        accepted = self.member_mt.invitations.accept(inv["token"])
        self.assertEqual(accepted["tenant_id"], tenant_id)
        self.assertTrue(accepted["membership_id"])

        # 5. UI Permission check (can)
        self.assertTrue(self.owner_mt.can(tenant_id, "documents.read"))
        self.assertTrue(self.owner_mt.can(tenant_id, "multitenancy.tenant.manage"))

        # 6. Tenant lifecycle: update, deactivate, reactivate
        updated_tenant = self.owner_mt.tenants.update(tenant_id, name="Python Renamed Org")
        self.assertEqual(updated_tenant["name"], "Python Renamed Org")

        deactivated = self.owner_mt.tenants.deactivate(tenant_id)
        self.assertFalse(deactivated["is_active"])

        reactivated = self.owner_mt.tenants.reactivate(tenant_id)
        self.assertTrue(reactivated["is_active"])

        # 7. Audit log check
        audit_events = self.owner_mt.audit.list(tenant_id)
        self.assertTrue(len(audit_events) >= 3)
        self.assertTrue(any(a["command"] == "tenant.create" for a in audit_events))


if __name__ == "__main__":
    unittest.main()
