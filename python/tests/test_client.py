import unittest

from supabase_multitenancy import ErrorCode, MultitenancyClient, MultitenancyError, build_accept_url


class Response:
    def __init__(self, data): self.data = data


class Builder:
    def __init__(self, result): self.result = result
    def execute(self):
        if isinstance(self.result, BaseException): raise self.result
        return Response({"api_version": 1, "data": self.result})


class FakeSupabase:
    def __init__(self, handler): self.handler = handler; self.calls = []
    def rpc(self, function_name, params):
        self.calls.append((function_name, params))
        return Builder(self.handler(function_name, params))
    def schema(self, _name):
        return self


class ClientTests(unittest.TestCase):
    def test_roles_are_read_only_context(self):
        transport = FakeSupabase(lambda _fn, _params: [{"id": "r1", "key": "editor", "name": "Editor"}])
        client = MultitenancyClient(transport)
        self.assertEqual(client.roles.list("t1")[0]["key"], "editor")
        self.assertEqual(transport.calls[0][0], "context")
        self.assertFalse(hasattr(client.roles, "create"))

    def test_member_grants_use_admin_rpc(self):
        transport = FakeSupabase(lambda _fn, params: params["p_payload"])
        client = MultitenancyClient(transport)
        client.members.set_grants("t1", "m1", [{"role_id": "r1", "scope_id": None}])
        self.assertEqual(transport.calls[0][0], "admin")
        self.assertEqual(transport.calls[0][1]["p_command"], "member.set_grants")

    def test_list_page_uses_context_page(self):
        transport = FakeSupabase(lambda _fn, _params: {"items": [{"key": "editor"}], "next_cursor": "next"})
        client = MultitenancyClient(transport)
        self.assertEqual(client.roles.list_page("t1", cursor="cursor", limit=10), {
            "items": [{"key": "editor"}], "next_cursor": "next"
        })
        self.assertEqual(transport.calls[0], ("context_page", {
            "p_tenant_id": "t1", "p_section": "roles", "p_cursor": "cursor", "p_limit": 10
        }))

    def test_grant_references_require_exactly_one_role_reference(self):
        transport = FakeSupabase(lambda _fn, _params: {})
        client = MultitenancyClient(transport)
        with self.assertRaises(ValueError):
            client.members.set_grants("t1", "m1", [{"role_id": "r1", "role_key": "editor"}])

    def test_role_commands_fail_before_network(self):
        transport = FakeSupabase(lambda _fn, _params: {})
        client = MultitenancyClient(transport)
        with self.assertRaises(ValueError):
            client.admin("t1", "role.create", {})
        self.assertEqual(transport.calls, [])

    def test_unknown_errors_remain_unknown(self):
        transport = FakeSupabase(lambda _fn, _params: RuntimeError("database exploded"))
        client = MultitenancyClient(transport)
        with self.assertRaises(MultitenancyError) as raised:
            client.roles.list("t1")
        self.assertEqual(raised.exception.code, ErrorCode.UNKNOWN)

    def test_accept_url_preserves_existing_query(self):
        self.assertEqual(
            build_accept_url("https://example.test/accept?lang=en", "secret token"),
            "https://example.test/accept?lang=en&token=secret+token",
        )


if __name__ == "__main__":
    unittest.main()
