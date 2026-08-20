import assert from "node:assert/strict";
import test from "node:test";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "../../src/sdk/client.js";
import { MultitenancyError } from "../../src/sdk/errors.js";

function mockClient(handler: (fn: string, params: Record<string, unknown>) => unknown): SupabaseClient {
  const client = {
    async rpc(fn: string, params: Record<string, unknown>) {
      try {
        return { data: { api_version: 1, data: handler(fn, params) }, error: null };
      } catch (error) {
        return { data: null, error };
      }
    },
    schema(_name: string) {
      return client;
    },
  };
  return client as unknown as SupabaseClient;
}

test("roles are read-only and fetched through context", async () => {
  const calls: Array<{ fn: string; params: Record<string, unknown> }> = [];
  const client = createMultitenancyClient(mockClient((fn, params) => {
    calls.push({ fn, params });
    return [{ id: "role-1", key: "editor", name: "Editor", permissions: [] }];
  }));

  const roles = await client.roles.list("tenant-1");
  assert.equal(roles[0].key, "editor");
  assert.deepEqual(Object.keys(client.roles), ["list", "listPage"]);
  assert.deepEqual(calls[0], {
    fn: "context",
    params: { p_tenant_id: "tenant-1", p_section: "roles", p_limit: 50 },
  });
});

test("listPage uses context_page and returns an opaque cursor", async () => {
  const calls: Array<{ fn: string; params: Record<string, unknown> }> = [];
  const client = createMultitenancyClient(mockClient((fn, params) => {
    calls.push({ fn, params });
    return { items: [{ key: "editor" }], next_cursor: "next" };
  }));

  const page = await client.roles.listPage("tenant-1", "cursor", 10);
  assert.deepEqual(page, { items: [{ key: "editor" }], nextCursor: "next" });
  assert.deepEqual(calls[0], {
    fn: "context_page",
    params: { p_tenant_id: "tenant-1", p_section: "roles", p_cursor: "cursor", p_limit: 10 },
  });
});

test("member grant assignment uses the single admin RPC", async () => {
  const calls: Array<{ fn: string; params: Record<string, unknown> }> = [];
  const client = createMultitenancyClient(mockClient((fn, params) => {
    calls.push({ fn, params });
    return { membership_id: "member-1", grants: params.p_payload && (params.p_payload as { grants: unknown }).grants };
  }));

  await client.members.setGrants("tenant-1", "member-1", [{ role_id: "role-1", scope_id: null }]);
  assert.equal(calls[0].fn, "admin");
  assert.equal(calls[0].params.p_command, "member.set_grants");
});

test("grant references require exactly one role id or key", async () => {
  const client = createMultitenancyClient(mockClient(() => ({})));
  await assert.rejects(
    () => client.members.setGrants("tenant-1", "member-1", [{ role_id: "r1", role_key: "editor" } as never]),
    (error: unknown) => error instanceof TypeError
  );
});

test("can unwraps the versioned RPC envelope", async () => {
  const client = createMultitenancyClient<"documents.read">(mockClient(() => ({ allowed: true })));
  assert.equal(await client.can("tenant-1", "documents.read", ["scope-1"]), true);
});

test("unknown database errors are not mislabeled as forbidden", async () => {
  const client = createMultitenancyClient(mockClient(() => {
    throw { message: "unexpected database failure", code: "XX000" };
  }));
  await assert.rejects(() => client.roles.list("tenant-1"), (error: unknown) => {
    return error instanceof MultitenancyError && error.code === "UNKNOWN";
  });
});
