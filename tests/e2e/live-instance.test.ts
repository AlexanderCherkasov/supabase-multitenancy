/**
 * Real local-stack HTTP/Auth/PostgREST tests.
 *
 * All user behaviour below uses an authenticated Supabase client and `api`.
 * The only direct database operation is a DBA migration-style insert of the
 * exceptional tenant-specific role after its tenant exists; there is no
 * service-role client, JWT GUC, or linked-project emulation in this suite.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL;
const anonKey = process.env.SUPABASE_ANON_KEY;
const dbUrl = process.env.SUPABASE_DB_URL;

if (!url || !anonKey || !dbUrl) {
  test("local HTTP/Auth/PostgREST E2E (environment unavailable)", { skip: true }, () => {});
} else {
  const runId = Math.random().toString(36).slice(2, 10);
  const password = `E2e!${runId}Password9`;

  type User = { id: string; email: string; token: string; client: SupabaseClient };
  type Scope = { id: string; key: string };
  type Role = { id: string; key: string; tenant_id: string | null };
  type Member = { id: string; user_id: string; status: string; grants?: Array<{ role_id: string }> };

  function api(client: SupabaseClient) {
    return client.schema("api");
  }

  async function createUser(label: string): Promise<User> {
    const email = `e2e-${label}-${runId}@example.test`;
    const client = createClient(url!, anonKey!, { auth: { persistSession: false } });
    const signedUp = await client.auth.signUp({ email, password });
    assert.ifError(signedUp.error);
    assert.ok(signedUp.data.user, "local Auth created a user");
    assert.ok(signedUp.data.session, "local Auth returned an authenticated session");
    return { id: signedUp.data.user.id, email, token: signedUp.data.session.access_token, client };
  }

  async function login(email: string): Promise<SupabaseClient> {
    const client = createClient(url!, anonKey!, { auth: { persistSession: false } });
    const result = await client.auth.signInWithPassword({ email, password });
    assert.ifError(result.error);
    assert.ok(result.data.session, "second authenticated client has a session");
    return client;
  }

  async function rpc<T>(client: SupabaseClient, fn: string, args: Record<string, unknown>): Promise<T> {
    const result = await api(client).rpc(fn, args);
    if (result.error) throw result.error;
    const envelope = result.data as { api_version?: number; data?: T } | null;
    assert.equal(envelope?.api_version, 1, `${fn} returns the API envelope`);
    return envelope?.data as T;
  }

  async function rpcFailure(client: SupabaseClient, fn: string, args: Record<string, unknown>) {
    const result = await api(client).rpc(fn, args);
    assert.ok(result.error, `${fn} must be denied`);
    return result.error;
  }

  function dbaInsertTenantRole(tenantId: string, roleKey: string): string {
    assert.match(tenantId, /^[0-9a-f-]{36}$/i);
    assert.match(roleKey, /^[a-z][a-z0-9_]{1,39}$/);
    const sql = `
      with created_role as (
        insert into multitenancy.roles (tenant_id, key, name, description)
        values ('${tenantId}'::uuid, '${roleKey}', 'E2E tenant reader', 'DBA-only tenant-specific role')
        returning id
      ), granted_permission as (
        insert into multitenancy.role_permissions (role_id, permission_id, access_level)
        select created_role.id, permissions.id, 'all'
        from created_role
        join multitenancy.permissions as permissions on permissions.key = 'documents.read'
      )
      select id from created_role;
    `;
    return execFileSync("psql", [dbUrl!, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql], {
      encoding: "utf8",
    }).trim();
  }

  function memberFor(members: Member[], userId: string): Member {
    const member = members.find((candidate) => candidate.user_id === userId);
    assert.ok(member, `membership exists for ${userId}`);
    return member;
  }

  async function members(owner: User, tenantId: string): Promise<Member[]> {
    return rpc<Member[]>(owner.client, "context", { p_tenant_id: tenantId, p_section: "members", p_limit: 100 });
  }

  async function inviteAndAccept(
    owner: User,
    recipient: User,
    tenantId: string,
    grants: Array<Record<string, string | null>>,
  ): Promise<{ membership_id: string }> {
    const invitation = await rpc<{ token: string }>(owner.client, "admin", {
      p_tenant_id: tenantId,
      p_command: "invitation.create",
      p_payload: { email: recipient.email, grants },
    });
    return rpc(recipient.client, "accept_invitation", { p_token: invitation.token });
  }

  test("v0.3 local HTTP/Auth/PostgREST authorization gate", async (t) => {
    const owner = await createUser("owner");
    const writer = await createUser("writer");
    const tenantManager = await createUser("tenant-manager");
    const tenantReader = await createUser("tenant-reader");
    const delegatedAdmin = await createUser("delegated-admin");
    const concurrentInvitee = await createUser("concurrent-invitee");
    const revokedInvitee = await createUser("revoked-invitee");
    const outsider = await createUser("outsider");

    const tenant = await rpc<{ tenant_id: string }>(owner.client, "create_tenant", {
      p_slug: `e2e-${runId}`, p_name: "HTTP E2E Tenant",
    });
    const tenantId = tenant.tenant_id;
    const otherTenant = await rpc<{ tenant_id: string }>(outsider.client, "create_tenant", {
      p_slug: `e2e-other-${runId}`, p_name: "Other HTTP E2E Tenant",
    });
    const otherTenantId = otherTenant.tenant_id;

    const tenantRoleKey = `e2e_tenant_${runId}`;
    const tenantRoleId = dbaInsertTenantRole(tenantId, tenantRoleKey);
    const foreignTenantRoleKey = `e2e_other_${runId}`;
    const foreignTenantRoleId = dbaInsertTenantRole(otherTenantId, foreignTenantRoleKey);
    assert.match(tenantRoleId, /^[0-9a-f-]{36}$/i, "DBA role seed returned an id");
    assert.match(foreignTenantRoleId, /^[0-9a-f-]{36}$/i, "foreign DBA role seed returned an id");

    const scopeOne = await rpc<Scope>(owner.client, "admin", {
      p_tenant_id: tenantId, p_command: "scope.create",
      p_payload: { kind: "project", key: "one", name: "Project One" },
    });
    const scopeTwo = await rpc<Scope>(owner.client, "admin", {
      p_tenant_id: tenantId, p_command: "scope.create",
      p_payload: { kind: "project", key: "two", name: "Project Two" },
    });
    const foreignScope = await rpc<Scope>(outsider.client, "admin", {
      p_tenant_id: otherTenantId, p_command: "scope.create",
      p_payload: { kind: "project", key: "foreign", name: "Foreign Project" },
    });

    await t.test("only exposed api accepts browser RPCs", async () => {
      const privateResponse = await fetch(`${url}/rest/v1/rpc/create_tenant`, {
        method: "POST",
        headers: {
          apikey: anonKey!, Authorization: `Bearer ${owner.token}`,
          "Content-Profile": "multitenancy", "content-type": "application/json",
        },
        body: JSON.stringify({ p_slug: `private-${runId}`, p_name: "Must not exist" }),
      });
      assert.equal(privateResponse.ok, false, "PostgREST does not expose multitenancy");
      const privateRpc = await owner.client.schema("multitenancy").rpc("create_tenant", {
        p_slug: `private-rpc-${runId}`, p_name: "Must not exist",
      });
      assert.ok(privateRpc.error, "authenticated client cannot invoke a private RPC");
    });

    await t.test("global and DBA tenant-specific roles are listed only in their tenant", async () => {
      const ownRoles = await rpc<Role[]>(owner.client, "context", {
        p_tenant_id: tenantId, p_section: "roles", p_limit: 100,
      });
      assert.ok(ownRoles.some((role) => role.key === "e2e_writer" && role.tenant_id === null));
      assert.ok(ownRoles.some((role) => role.key === tenantRoleKey && role.tenant_id === tenantId));
      const foreignRoles = await rpc<Role[]>(outsider.client, "context", {
        p_tenant_id: otherTenantId, p_section: "roles", p_limit: 100,
      });
      assert.ok(foreignRoles.some((role) => role.key === "e2e_writer"));
      assert.equal(foreignRoles.some((role) => role.key === tenantRoleKey), false);

      const firstPage = await rpc<{ items: Role[]; nextCursor: string | null }>(owner.client, "context_page", {
        p_tenant_id: tenantId, p_section: "roles", p_limit: 1,
      });
      assert.equal(firstPage.items.length, 1);
      assert.ok(firstPage.nextCursor, "keyset page supplies an opaque continuation");
      const secondPage = await rpc<{ items: Role[]; nextCursor: string | null }>(owner.client, "context_page", {
        p_tenant_id: tenantId, p_section: "roles", p_cursor: firstPage.nextCursor, p_limit: 1,
      });
      assert.equal(secondPage.items.length, 1);
      assert.notEqual(firstPage.items[0]?.id, secondPage.items[0]?.id);
      const badCursor = await rpcFailure(owner.client, "context_page", {
        p_tenant_id: tenantId, p_section: "roles", p_cursor: "not-an-opaque-cursor", p_limit: 1,
      });
      assert.equal(badCursor.code, "22023");
      assert.match(badCursor.message, /INVALID_CURSOR/);
    });

    const roleList = await rpc<Role[]>(owner.client, "context", {
      p_tenant_id: tenantId, p_section: "roles", p_limit: 100,
    });
    const writerRole = roleList.find((role) => role.key === "e2e_writer");
    const managerRole = roleList.find((role) => role.key === "e2e_manager");
    assert.ok(writerRole && managerRole, "global DBA roles are visible");

    const writerInvitation = await rpc<{ token: string }>(owner.client, "admin", {
      p_tenant_id: tenantId, p_command: "invitation.create",
      p_payload: { email: writer.email, grants: [{ role_id: writerRole.id, scope_id: scopeOne.id }] },
    });
    const writerSecondClient = await login(writer.email);
    const accepted = await Promise.all([
      rpc<{ membership_id: string }>(writer.client, "accept_invitation", { p_token: writerInvitation.token }),
      rpc<{ membership_id: string }>(writerSecondClient, "accept_invitation", { p_token: writerInvitation.token }),
    ]);
    assert.equal(accepted[0].membership_id, accepted[1].membership_id, "concurrent acceptance is idempotent");

    await t.test("grant references reject foreign roles/scopes and keep existing assignments", async () => {
      const writerMembership = memberFor(await members(owner, tenantId), writer.id);
      const deniedPayloads = [
        { role_id: foreignTenantRoleId, scope_id: scopeOne.id },
        { role_key: foreignTenantRoleKey, scope_id: scopeOne.id },
        { role_id: writerRole.id, scope_id: foreignScope.id },
        { scope_id: scopeOne.id },
        { role_id: writerRole.id, role_key: "e2e_writer", scope_id: scopeOne.id },
      ];
      for (const grants of deniedPayloads) {
        const denied = await rpcFailure(owner.client, "admin", {
          p_tenant_id: tenantId,
          p_command: "member.set_grants",
          p_payload: { membership_id: writerMembership.id, grants: [grants] },
        });
        assert.equal(denied.code, "22P02");
      }
      const afterFailures = memberFor(await members(owner, tenantId), writer.id);
      assert.ok(
        afterFailures.grants?.some((grant) => grant.role_id === writerRole.id),
        "grant validation runs before replacing assignments",
      );
    });

    await inviteAndAccept(owner, tenantManager, tenantId, [{ role_key: "e2e_manager", scope_id: null }]);
    await inviteAndAccept(owner, tenantReader, tenantId, [{ role_key: tenantRoleKey, scope_id: scopeOne.id }]);
    await inviteAndAccept(owner, delegatedAdmin, tenantId, [{ role_key: "e2e_limited_admin", scope_id: null }]);

    await t.test("scope, own/all, and cross-tenant PostgREST isolation hold", async () => {
      const ownerOne = await owner.client.from("documents").insert({
        tenant_id: tenantId, project_id: scopeOne.id, author_id: owner.id, title: "owner scope one",
      }).select("id, tenant_id, project_id").single();
      assert.ifError(ownerOne.error);
      assert.ok(ownerOne.data);
      const ownerTwo = await owner.client.from("documents").insert({
        tenant_id: tenantId, project_id: scopeTwo.id, author_id: owner.id, title: "owner scope two",
      }).select("id").single();
      assert.ifError(ownerTwo.error);
      assert.ok(ownerTwo.data);
      const ownerUnscoped = await owner.client.from("documents").insert({
        tenant_id: tenantId, project_id: null, author_id: owner.id, title: "owner unscoped doc",
      }).select("id, project_id").single();
      assert.ifError(ownerUnscoped.error);
      assert.ok(ownerUnscoped.data);

      const ownInsert = await writer.client.from("documents").insert({
        tenant_id: tenantId, project_id: scopeOne.id, author_id: writer.id, title: "writer scope one",
      }).select("id, project_id").single();
      assert.ifError(ownInsert.error);
      assert.ok(ownInsert.data);

      const writerRows = await writer.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(writerRows.error);
      assert.deepEqual(writerRows.data?.map((row) => row.id), [ownInsert.data.id]);

      const managerRows = await tenantManager.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(managerRows.error);
      assert.ok(managerRows.data?.some((row) => row.id === ownerUnscoped.data.id), "tenant manager sees unscoped document with project_id null");
      assert.ok(managerRows.data?.some((row) => row.id === ownerOne.data.id), "tenant manager sees scoped document");

      const wrongScope = await writer.client.from("documents").insert({
        tenant_id: tenantId, project_id: scopeTwo.id, author_id: writer.id, title: "writer wrong scope",
      });
      assert.ok(wrongScope.error, "scope-specific role cannot create in another scope");
      const specialRows = await tenantReader.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(specialRows.error);
      assert.ok(specialRows.data?.some((row) => row.id === ownerOne.data.id), "tenant-specific all role reads its scope");
      assert.equal(specialRows.data?.some((row) => row.id === ownerTwo.data.id), false, "tenant-specific role cannot read another scope");
      assert.equal(specialRows.data?.some((row) => row.id === ownerUnscoped.data.id), false, "scoped reader cannot read unscoped doc");
      const outsiderRead = await outsider.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(outsiderRead.error);
      assert.equal(outsiderRead.data?.length ?? 0, 0, "other tenant sees no rows");
      const outsiderInsert = await outsider.client.from("documents").insert({
        tenant_id: tenantId, project_id: scopeOne.id, author_id: outsider.id, title: "cross tenant",
      });
      assert.ok(outsiderInsert.error, "other tenant cannot write rows");
    });

    await t.test("protected tenant and scope keys cannot be transferred", async () => {
      const owned = await owner.client.from("documents").select("id").eq("tenant_id", tenantId).eq("project_id", scopeOne.id).eq("author_id", owner.id).single();
      assert.ifError(owned.error);
      assert.ok(owned.data);
      const moveScope = await owner.client.from("documents").update({ project_id: scopeTwo.id }).eq("id", owned.data.id);
      assert.ok(moveScope.error);
      assert.match(moveScope.error.message, /PROTECTED_KEY_IMMUTABLE/);
      const moveTenant = await owner.client.from("documents").update({ tenant_id: otherTenantId }).eq("id", owned.data.id);
      assert.ok(moveTenant.error);
      assert.match(moveTenant.error.message, /PROTECTED_KEY_IMMUTABLE/);
    });

    await t.test("delegated admins cannot escalate grants or mutate DBA role definitions", async () => {
      const writerMembership = memberFor(await members(owner, tenantId), writer.id);
      const escalation = await rpcFailure(delegatedAdmin.client, "admin", {
        p_tenant_id: tenantId, p_command: "member.set_grants",
        p_payload: { membership_id: writerMembership.id, grants: [{ role_id: managerRole.id, scope_id: null }] },
      });
      assert.equal(escalation.code, "42501");
      assert.match(escalation.message, /ROLE_ESCALATION/);
      const afterFailure = memberFor(await members(owner, tenantId), writer.id);
      assert.ok(afterFailure.grants?.some((grant) => grant.role_id === writerRole.id), "failed escalation keeps previous grants");
      const roleMutation = await rpcFailure(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "role.create", p_payload: { key: "not-allowed" },
      });
      assert.equal(roleMutation.code, "42501");
      assert.match(roleMutation.message, /DBA-managed/);
    });

    await t.test("suspend and remove immediately revoke a live session", async () => {
      const writerMembership = memberFor(await members(owner, tenantId), writer.id);
      const suspended = await rpc<{ status: string }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "member.suspend", p_payload: { membership_id: writerMembership.id },
      });
      assert.equal(suspended.status, "suspended");
      const suspendedRead = await writer.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(suspendedRead.error);
      assert.equal(suspendedRead.data?.length ?? 0, 0);
      const reactivated = await rpc<{ status: string }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "member.reactivate", p_payload: { membership_id: writerMembership.id },
      });
      assert.equal(reactivated.status, "active");
      const restoredRead = await writer.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(restoredRead.error);
      assert.equal(restoredRead.data?.length, 1, "active membership restores the existing grant");
      const removed = await rpc<{ status: string }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "member.remove", p_payload: { membership_id: writerMembership.id },
      });
      assert.equal(removed.status, "removed");
      const removedRead = await writer.client.from("documents").select("id").eq("tenant_id", tenantId);
      assert.ifError(removedRead.error);
      assert.equal(removedRead.data?.length ?? 0, 0);
    });

    await t.test("invitation acceptance serializes concurrent browser clients", async () => {
      const invitation = await rpc<{ token: string }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "invitation.create",
        p_payload: { email: concurrentInvitee.email, grants: [{ role_key: "e2e_writer", scope_id: scopeOne.id }] },
      });
      const secondClient = await login(concurrentInvitee.email);
      const concurrent = await Promise.all([
        rpc<{ membership_id: string }>(concurrentInvitee.client, "accept_invitation", { p_token: invitation.token }),
        rpc<{ membership_id: string }>(secondClient, "accept_invitation", { p_token: invitation.token }),
      ]);
      assert.equal(concurrent[0].membership_id, concurrent[1].membership_id);
      const inviteeMembers = (await members(owner, tenantId)).filter((member) => member.user_id === concurrentInvitee.id);
      assert.equal(inviteeMembers.length, 1, "concurrent accept created exactly one membership");
    });

    await t.test("revoked invitation cannot be accepted by its authenticated recipient", async () => {
      const invitation = await rpc<{ invitation_id: string; token: string }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "invitation.create",
        p_payload: { email: revokedInvitee.email, grants: [{ role_key: "e2e_writer", scope_id: scopeOne.id }] },
      });
      const revoked = await rpc<{ revoked: boolean }>(owner.client, "admin", {
        p_tenant_id: tenantId, p_command: "invitation.revoke", p_payload: { invitation_id: invitation.invitation_id },
      });
      assert.equal(revoked.revoked, true);
      const denied = await rpcFailure(revokedInvitee.client, "accept_invitation", { p_token: invitation.token });
      assert.equal(denied.code, "28000");
      assert.match(denied.message, /TOKEN_REVOKED/);
    });
  });
}
