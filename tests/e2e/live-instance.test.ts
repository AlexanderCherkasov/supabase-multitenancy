import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { createMultitenancyClient, MultitenancyError } from "../../src/index.js";

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.log("Skipping live instance E2E tests: SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY are not set in environment.");
  process.exit(0);
}

const runId = Math.random().toString(36).substring(2, 8);
const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

function runDbaSql(sql: string): string {
  const tmpFile = join(tmpdir(), `query_${Date.now()}_${Math.random().toString(36).substring(2)}.sql`);
  writeFileSync(tmpFile, sql, "utf8");
  try {
    return execSync(`supabase db query --linked --file "${tmpFile}"`, { stdio: "pipe", encoding: "utf8" });
  } finally {
    try {
      unlinkSync(tmpFile);
    } catch {
      // ignore
    }
  }
}

function runUserRpc(userId: string | null, fnName: string, params: Record<string, unknown>): unknown {
  const paramList: string[] = [];
  if (fnName === "create_tenant") {
    paramList.push(`'${params.p_slug}'`, `'${params.p_name}'`);
  } else if (fnName === "can") {
    const scopeParam = params.p_scope_ids
      ? `array[${(params.p_scope_ids as string[]).map((s) => `'${s}'::uuid`).join(",")}]`
      : "null::uuid[]";
    paramList.push(`'${params.p_tenant_id}'::uuid`, `'${params.p_permission}'`, scopeParam);
  } else if (fnName === "context") {
    const cursor = params.p_cursor ? `'${params.p_cursor}'` : "null";
    paramList.push(`'${params.p_tenant_id}'::uuid`, `'${params.p_section}'`, cursor, `${params.p_limit || 50}`);
  } else if (fnName === "invitation_preview") {
    paramList.push(`'${params.p_token}'`);
  } else if (fnName === "accept_invitation") {
    paramList.push(`'${params.p_token}'`);
  } else if (fnName === "admin") {
    const payloadJson = JSON.stringify(params.p_payload || {}).replace(/'/g, "''");
    paramList.push(`'${params.p_tenant_id}'::uuid`, `'${params.p_command}'`, `'${payloadJson}'::jsonb`);
  }

  const roleSetting = userId ? "authenticated" : "anon";
  const userIdVal = userId || "";

  const sql = `
    select
      set_config('request.jwt.claim.sub', '${userIdVal}', true),
      set_config('request.jwt.claim.role', '${roleSetting}', true),
      multitenancy.${fnName}(${paramList.join(",")}) as result;
  `.trim();

  try {
    const out = runDbaSql(sql);
    const parsed = JSON.parse(out);
    const rawResult = parsed.rows?.[0]?.result;
    return typeof rawResult === "string" ? JSON.parse(rawResult) : rawResult;
  } catch (err: unknown) {
    const errorObj = err as { message?: string; stdout?: string | Buffer; stderr?: string | Buffer };
    const stdoutStr = errorObj.stdout ? String(errorObj.stdout) : "";
    const stderrStr = errorObj.stderr ? String(errorObj.stderr) : "";
    const msg = `${errorObj.message || ""} ${stdoutStr} ${stderrStr}`;
    if (msg.includes("ROLE_ESCALATION")) {
      throw new MultitenancyError("ROLE_ESCALATION", msg);
    }
    if (msg.includes("EMAIL_MISMATCH")) {
      throw new MultitenancyError("EMAIL_MISMATCH", msg);
    }
    if (msg.includes("42501") || msg.includes("FORBIDDEN")) {
      throw new MultitenancyError("FORBIDDEN", msg);
    }
    if (msg.includes("23505") || msg.includes("CONFLICT")) {
      throw new MultitenancyError("CONFLICT", msg);
    }
    if (msg.includes("22P02") || msg.includes("INVALID_INPUT")) {
      throw new MultitenancyError("INVALID_INPUT", msg);
    }
    if (msg.includes("TOKEN_REVOKED")) {
      throw new MultitenancyError("TOKEN_REVOKED", msg);
    }
    if (msg.includes("TOKEN_EXPIRED")) {
      throw new MultitenancyError("TOKEN_EXPIRED", msg);
    }
    if (msg.includes("TOKEN_ACCEPTED")) {
      throw new MultitenancyError("TOKEN_ACCEPTED", msg);
    }
    if (msg.includes("28000") || msg.includes("TOKEN_INVALID")) {
      throw new MultitenancyError("TOKEN_INVALID", msg);
    }
    if (msg.includes("42704") || msg.includes("NOT_FOUND")) {
      throw new MultitenancyError("NOT_FOUND", msg);
    }
    throw new MultitenancyError("UNKNOWN", msg);
  }
}

function createUserMultitenancyClient(client: SupabaseClient, userId: string | null) {
  const fakeClient = {
    async rpc(fn: string, params: Record<string, unknown>) {
      try {
        const data = runUserRpc(userId, fn, params);
        return { data, error: null };
      } catch (error) {
        return { data: null, error };
      }
    },
    schema(_s: string) {
      return this;
    },
  } as unknown as SupabaseClient;

  return createMultitenancyClient<"documents.read" | "documents.create" | "documents.update" | "documents.delete">(
    fakeClient
  );
}

interface TestUser {
  id: string;
  email: string;
  password: string;
  client: SupabaseClient;
  mt: ReturnType<typeof createUserMultitenancyClient>;
}

async function createAndSignInUser(label: string): Promise<TestUser> {
  const email = `test-${label}-${runId}@example.com`;
  const password = `TestPass!${runId}99`;

  const { data: created, error: createError } = await adminClient.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { display_name: `User ${label}` },
  });
  if (createError || !created.user) {
    throw new Error(`Failed to create user ${email}: ${createError?.message}`);
  }

  const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { error: signInError } = await client.auth.signInWithPassword({ email, password });
  if (signInError) {
    throw new Error(`Failed to sign in ${email}: ${signInError.message}`);
  }

  const mt = createUserMultitenancyClient(client, created.user.id);
  return { id: created.user.id, email, password, client, mt };
}

test("Live Supabase E2E Test Suite (PostgREST + Auth + multitenancy Schema RPC + RLS)", async (t) => {
  let ownerA: TestUser;
  let managerA: TestUser;
  let memberA: TestUser;
  let userB: TestUser;

  let tenantAId: string;
  let tenantBId: string;
  let scope1Id: string;
  let scope2Id: string;
  let editorRoleId: string;
  let managerRoleId: string;

  await t.test("1. Provision test users via Supabase Auth", async () => {
    ownerA = await createAndSignInUser("owner-a");
    managerA = await createAndSignInUser("manager-a");
    memberA = await createAndSignInUser("member-a");
    userB = await createAndSignInUser("user-b");

    assert.ok(ownerA.id, "Owner A created");
    assert.ok(managerA.id, "Manager A created");
    assert.ok(memberA.id, "Member A created");
    assert.ok(userB.id, "User B created");
  });

  await t.test("2. Tenant creation (multitenancy.create_tenant) and validation", async () => {
    const slugA = `tenant-a-${runId}`;
    const slugB = `tenant-b-${runId}`;

    const createdA = await ownerA.mt.createTenant({ slug: slugA, name: "Tenant A Org" });
    tenantAId = createdA.tenant_id;
    assert.equal(createdA.slug, slugA);
    assert.equal(createdA.name, "Tenant A Org");

    const createdB = await userB.mt.createTenant({ slug: slugB, name: "Tenant B Org" });
    tenantBId = createdB.tenant_id;
    assert.ok(tenantBId);

    // Conflict test: duplicate slug
    await assert.rejects(
      async () => ownerA.mt.createTenant({ slug: slugA, name: "Duplicate" }),
      (err: unknown) => err instanceof MultitenancyError && err.code === "CONFLICT"
    );

    // Invalid slug pattern test
    await assert.rejects(
      async () => ownerA.mt.createTenant({ slug: "INVALID SLUG!", name: "Bad Slug" }),
      (err: unknown) => err instanceof MultitenancyError && err.code === "INVALID_INPUT"
    );
  });

  await t.test("3. Seed DBA-managed role profiles for Tenant A in multitenancy schema", async () => {
    // Verify client/RPC role mutation is blocked (roles are DBA-managed)
    await assert.rejects(
      async () => ownerA.mt.admin(tenantAId, { command: "role.create" as never, payload: {} }),
      (err: unknown) => err instanceof MultitenancyError && err.code === "FORBIDDEN"
    );

    // Seed roles using DBA SQL migration
    runDbaSql(`
      do $$
      declare
        v_tid uuid := '${tenantAId}'::uuid;
        v_editor_id uuid;
        v_manager_id uuid;
      begin
        insert into multitenancy.roles (tenant_id, key, name, description)
        values (v_tid, 'editor', 'Editor', 'Can edit owned documents')
        on conflict (tenant_id, key) do update set name = excluded.name
        returning id into v_editor_id;

        insert into multitenancy.role_permissions (role_id, permission_id, access_level)
        select v_editor_id, p.id, grants.access_level
        from (values
          ('documents.read', 'all'),
          ('documents.create', 'own'),
          ('documents.update', 'own'),
          ('documents.delete', 'own')
        ) as grants(permission_key, access_level)
        join multitenancy.permissions p on p.key = grants.permission_key
        on conflict (role_id, permission_id) do update set access_level = excluded.access_level;

        insert into multitenancy.roles (tenant_id, key, name, description)
        values (v_tid, 'manager', 'Manager', 'Can manage members and scopes')
        on conflict (tenant_id, key) do update set name = excluded.name
        returning id into v_manager_id;

        insert into multitenancy.role_permissions (role_id, permission_id, access_level)
        select v_manager_id, p.id, grants.access_level
        from (values
          ('multitenancy.members.read', 'all'),
          ('multitenancy.members.manage', 'all'),
          ('multitenancy.members.invite', 'all'),
          ('multitenancy.scopes.manage', 'all'),
          ('multitenancy.audit.read', 'all'),
          ('documents.read', 'all')
        ) as grants(permission_key, access_level)
        join multitenancy.permissions p on p.key = grants.permission_key
        on conflict (role_id, permission_id) do update set access_level = excluded.access_level;
      end$$;
    `);

    const rolesContext = await ownerA.mt.roles.list(tenantAId);
    assert.equal(rolesContext.length, 2);
    const editorRole = rolesContext.find((r) => r.key === "editor");
    const managerRole = rolesContext.find((r) => r.key === "manager");
    assert.ok(editorRole);
    assert.ok(managerRole);
    editorRoleId = editorRole.id;
    managerRoleId = managerRole.id;
  });

  await t.test("4. Scope management (scope.create, scope.update, scope.delete)", async () => {
    const s1 = await ownerA.mt.scopes.create(tenantAId, {
      kind: "project",
      key: `frontend-${runId}`,
      name: "Frontend App",
      metadata: { env: "production" },
    });
    scope1Id = s1.id;
    assert.equal(s1.key, `frontend-${runId}`);

    const s2 = await ownerA.mt.scopes.create(tenantAId, {
      kind: "project",
      key: `backend-${runId}`,
      name: "Backend App",
    });
    scope2Id = s2.id;
    assert.ok(scope2Id);

    const updated = await ownerA.mt.scopes.update(tenantAId, scope1Id, {
      name: "Frontend Web Application",
    });
    assert.equal(updated.name, "Frontend Web Application");

    const scopesList = await ownerA.mt.scopes.list(tenantAId);
    assert.equal(scopesList.length, 2);

    // Cross-tenant outsider attempting to create scope on Tenant A
    await assert.rejects(
      async () =>
        userB.mt.scopes.create(tenantAId, { kind: "project", key: "hacked", name: "Hacked" }),
      (err: unknown) => err instanceof MultitenancyError && err.code === "FORBIDDEN"
    );
  });

  await t.test(
    "5. Invitations lifecycle (create, preview as anon, accept, replay, revoke)",
    async () => {
      // Owner A invites managerA with manager role
      const inv = await ownerA.mt.invitations.create(tenantAId, {
        email: managerA.email,
        grants: [{ role_id: managerRoleId }],
      });
      assert.ok(inv.invitation_id);
      assert.ok(inv.token);

      // Anonymous preview
      const anonClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
      const anonMt = createUserMultitenancyClient(anonClient, null);
      const preview = await anonMt.invitations.preview(inv.token);
      assert.equal(preview.valid, true);
      assert.equal(preview.tenant_id, tenantAId);
      assert.ok(preview.email_masked.includes("***"));
      assert.ok(preview.grants.some((g) => g.role === "manager"));

      // User B (email mismatch) attempts to accept managerA's invite
      await assert.rejects(
        async () => userB.mt.invitations.accept(inv.token),
        (err: unknown) => err instanceof MultitenancyError && err.code === "EMAIL_MISMATCH"
      );

      // managerA accepts
      const accepted = await managerA.mt.invitations.accept(inv.token);
      assert.equal(accepted.tenant_id, tenantAId);
      assert.ok(accepted.membership_id);

      // Idempotent re-accept by managerA
      const reaccepted = await managerA.mt.invitations.accept(inv.token);
      assert.equal(reaccepted.membership_id, accepted.membership_id);

      // Invitation revoke test
      const dummyEmail = `revoke-test-${runId}@example.com`;
      const invToRevoke = await ownerA.mt.invitations.create(tenantAId, {
        email: dummyEmail,
        grants: [],
      });
      await ownerA.mt.invitations.revoke(tenantAId, invToRevoke.invitation_id);

      await assert.rejects(
        async () => anonMt.invitations.preview(invToRevoke.token),
        (err: unknown) => err instanceof MultitenancyError && err.code === "TOKEN_REVOKED"
      );
    }
  );

  await t.test("6. Context sections inspection (multitenancy.context)", async () => {
    const selfCtx = await ownerA.mt.tenants.getSelf(tenantAId);
    assert.equal(selfCtx.is_owner, true);
    assert.equal(selfCtx.tenant.id, tenantAId);

    const perms = await ownerA.mt.permissions.list(tenantAId);
    assert.ok(perms.some((p) => p.key === "multitenancy.members.manage"));
    assert.ok(perms.some((p) => p.key === "documents.read"));

    const members = await ownerA.mt.members.list(tenantAId);
    assert.ok(members.length >= 2, "Owner and Manager are in members list");

    const audit = await ownerA.mt.audit.list(tenantAId);
    assert.ok(audit.length >= 2, "Audit contains events");
    assert.ok(audit.some((a) => a.command === "tenant.create"));
    assert.ok(audit.some((a) => a.command === "invitation.create"));
  });

  await t.test("7. Member role assignment and Anti-Escalation check", async () => {
    // Owner invites memberA with editor role scoped to Scope 1
    const invMember = await ownerA.mt.invitations.create(tenantAId, {
      email: memberA.email,
      grants: [{ role_id: editorRoleId, scope_id: scope1Id }],
    });
    const acceptedMember = await memberA.mt.invitations.accept(invMember.token);
    const memberMembershipId = acceptedMember.membership_id;

    // Verify member has the scoped grant
    const members = await ownerA.mt.members.list(tenantAId);
    const memberRecord = members.find((m) => m.id === memberMembershipId);
    assert.ok(memberRecord);
    assert.ok(
      memberRecord.grants?.some((g) => g.role_id === editorRoleId && g.scope_id === scope1Id)
    );

    // Manager A (who has multitenancy.members.manage but NOT documents.create/update/delete)
    // attempts to grant editor role to another member -> must be rejected by ROLE_ESCALATION
    await assert.rejects(
      async () =>
        managerA.mt.members.setGrants(tenantAId, memberMembershipId, [
          { role_id: editorRoleId, scope_id: scope1Id },
        ]),
      (err: unknown) => err instanceof MultitenancyError && err.code === "ROLE_ESCALATION"
    );
  });

  await t.test("8. UI Authorization helper (multitenancy.can)", async () => {
    // Owner has bypass (all permissions)
    assert.equal(await ownerA.mt.can(tenantAId, "documents.read"), true);
    assert.equal(await ownerA.mt.can(tenantAId, "multitenancy.tenant.manage"), true);

    // Member A has documents.read on Scope 1
    assert.equal(await memberA.mt.can(tenantAId, "documents.read", [scope1Id]), true);
    // Member A does NOT have documents.read on Scope 2
    assert.equal(await memberA.mt.can(tenantAId, "documents.read", [scope2Id]), false);

    // Outsider User B has no access to Tenant A
    assert.equal(await userB.mt.can(tenantAId, "documents.read"), false);
  });

  await t.test(
    "9. PostgREST Application Table RLS and Trigger Protection (public.documents)",
    async () => {
      // 1. Owner A inserts Document 1 in Scope 1
      const { data: doc1, error: doc1Err } = await ownerA.client
        .from("documents")
        .insert({
          tenant_id: tenantAId,
          project_id: scope1Id,
          author_id: ownerA.id,
          title: "Owner Doc 1",
          body: "Initial content",
        })
        .select()
        .single();
      assert.ifError(doc1Err);
      assert.equal(doc1.title, "Owner Doc 1");

      // 2. Member A inserts Document 2 in Scope 1 (allowed by documents.create: own)
      const { data: doc2, error: doc2Err } = await memberA.client
        .from("documents")
        .insert({
          tenant_id: tenantAId,
          project_id: scope1Id,
          author_id: memberA.id,
          title: "Member Doc 2",
          body: "Created by Member A",
        })
        .select()
        .single();
      assert.ifError(doc2Err);
      assert.equal(doc2.title, "Member Doc 2");

      // 3. Member A attempts to insert Document in Scope 2 (denied by RLS)
      const { error: deniedInsertErr } = await memberA.client.from("documents").insert({
        tenant_id: tenantAId,
        project_id: scope2Id,
        author_id: memberA.id,
        title: "Forbidden Doc",
      });
      assert.ok(deniedInsertErr, "Insert into Scope 2 denied for Member A");

      // 4. Member A reads documents in Scope 1 (documents.read: all allows reading all docs in scope)
      const { data: memberReadDocs, error: memberReadErr } = await memberA.client
        .from("documents")
        .select("*")
        .eq("tenant_id", tenantAId)
        .eq("project_id", scope1Id);
      assert.ifError(memberReadErr);
      assert.equal(memberReadDocs.length, 2, "Member A can read all docs in Scope 1");

      // 5. Member A updates own document (doc2) -> Allowed
      const { error: updateOwnErr } = await memberA.client
        .from("documents")
        .update({ title: "Member Doc 2 Updated" })
        .eq("id", doc2.id);
      assert.ifError(updateOwnErr);

      // 6. Member A attempts to update Owner A's document (doc1) -> Denied by RLS (0 rows updated)
      const { data: updateOtherResult, error: updateOtherErr } = await memberA.client
        .from("documents")
        .update({ title: "Hacked Doc 1" })
        .eq("id", doc1.id)
        .select();
      assert.ifError(updateOtherErr);
      assert.equal(updateOtherResult?.length, 0, "Member A cannot update Doc 1 (not author)");

      // 7. Cross-tenant isolation: User B queries documents -> receives 0 rows
      const { data: userBDocs, error: userBReadErr } = await userB.client
        .from("documents")
        .select("*")
        .eq("tenant_id", tenantAId);
      assert.ifError(userBReadErr);
      assert.equal(userBDocs?.length, 0, "User B cannot read Tenant A documents");

      // 8. Cross-tenant isolation: User B insert into Tenant A is denied
      const { error: userBInsertErr } = await userB.client.from("documents").insert({
        tenant_id: tenantAId,
        project_id: scope1Id,
        author_id: userB.id,
        title: "Cross-Tenant Doc",
      });
      assert.ok(userBInsertErr, "User B insert into Tenant A rejected by RLS");

      // 9. Immutable keys trigger: Owner A attempts to move document to Tenant B
      const { error: moveTenantErr } = await ownerA.client
        .from("documents")
        .update({ tenant_id: tenantBId })
        .eq("id", doc1.id);
      assert.ok(moveTenantErr, "Moving document across tenants blocked by trigger");
    }
  );

  await t.test("10. Membership suspension, reactivation, and removal", async () => {
    const members = await ownerA.mt.members.list(tenantAId);
    const memberRecord = members.find((m) => m.user_id === memberA.id);
    assert.ok(memberRecord);

    // Suspend member
    const suspended = await ownerA.mt.members.suspend(tenantAId, memberRecord.id);
    assert.equal(suspended.status, "suspended");

    // Suspended member cannot access context
    await assert.rejects(
      async () => memberA.mt.tenants.getSelf(tenantAId),
      (err: unknown) => err instanceof MultitenancyError && err.code === "FORBIDDEN"
    );

    // Reactivate member
    const reactivated = await ownerA.mt.members.reactivate(tenantAId, memberRecord.id);
    assert.equal(reactivated.status, "active");

    // Remove member
    const removed = await ownerA.mt.members.remove(tenantAId, memberRecord.id);
    assert.equal(removed.status, "removed");
  });

  await t.test("11. Tenant deactivation, reactivation, and ownership transfer", async () => {
    // Deactivate tenant
    const deactivated = await ownerA.mt.tenants.deactivate(tenantAId);
    assert.equal(deactivated.is_active, false);

    // Reactivate tenant
    const reactivated = await ownerA.mt.tenants.reactivate(tenantAId);
    assert.equal(reactivated.is_active, true);

    // Transfer ownership to managerA (active member)
    const transferred = await ownerA.mt.tenants.transferOwnership(tenantAId, managerA.id);
    assert.equal(transferred.owner_user_id, managerA.id);

    // managerA is now the owner
    const newSelf = await managerA.mt.tenants.getSelf(tenantAId);
    assert.equal(newSelf.is_owner, true);

    // Previous owner can no longer transfer ownership
    await assert.rejects(
      async () => ownerA.mt.tenants.transferOwnership(tenantAId, memberA.id),
      (err: unknown) => err instanceof MultitenancyError && err.code === "FORBIDDEN"
    );
  });

  await t.test("12. Audit Log Invariants (Append-only protection)", async () => {
    // Verify audit log has recorded administrative history
    const auditEvents = await managerA.mt.audit.list(tenantAId);
    assert.ok(auditEvents.length > 5, "Audit contains events");

    // Attempting to UPDATE or DELETE audit_events is blocked by trigger
    assert.throws(() => {
      runDbaSql(`delete from multitenancy.audit_events where tenant_id = '${tenantAId}'::uuid`);
    });
  });

  await t.test("13. Cleanup test data", async () => {
    const usersToDelete = [ownerA?.id, managerA?.id, memberA?.id, userB?.id].filter(Boolean);
    for (const uid of usersToDelete) {
      await adminClient.auth.admin.deleteUser(uid);
    }
  });
});
