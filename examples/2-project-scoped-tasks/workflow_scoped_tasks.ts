import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-multitenancy";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL!;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;

  const supabase = createClient(supabaseUrl, supabaseAnonKey);
  const mt = createMultitenancyClient(supabase);

  // ==========================================================================
  // 1. OWNER SETUP: Create Tenant and 2 Separate Project Scopes
  // ==========================================================================
  await supabase.auth.signInWithPassword({
    email: "owner@acme.com",
    password: "password123",
  });

  // 1a. Create Organization Tenant
  const { tenant_id } = await mt.createTenant({
    slug: "acme-corp",
    name: "Acme Corporation",
  });
  console.log("Tenant created:", tenant_id);

  // 1b. Create Scope 1: Project Alpha
  const { scope_id: projectAlphaId } = await mt.scopes.create(tenant_id, {
    kind: "project",
    key: "project-alpha",
    name: "Project Alpha (Mobile)",
  });

  // 1c. Create Scope 2: Project Beta
  const { scope_id: projectBetaId } = await mt.scopes.create(tenant_id, {
    kind: "project",
    key: "project-beta",
    name: "Project Beta (Web App)",
  });
  console.log(`Created Scopes -> Alpha: ${projectAlphaId}, Beta: ${projectBetaId}`);

  // Fetch DBA-defined role IDs
  const roles = await mt.roles.list(tenant_id);
  const editorRole = roles.find((r) => r.key === "task_editor")!;
  const managerRole = roles.find((r) => r.key === "task_manager")!;

  // ==========================================================================
  // 2. INVITE MEMBERS WITH DIFFERENT SCOPE RESTRICTIONS
  // ==========================================================================

  // Alice: Manager for the ENTIRE TENANT (scope_id: null)
  const aliceInvite = await mt.invitations.create(tenant_id, {
    email: "alice@acme.com",
    grants: [{ role_id: managerRole.id, scope_id: null }], // Global grant
  });

  // Bob: Editor RESTRICTED TO PROJECT ALPHA ONLY (scope_id: projectAlphaId)
  const bobInvite = await mt.invitations.create(tenant_id, {
    email: "bob@acme.com",
    grants: [{ role_id: editorRole.id, scope_id: projectAlphaId }], // Scoped grant
  });

  // Charlie: Editor RESTRICTED TO PROJECT BETA ONLY (scope_id: projectBetaId)
  const charlieInvite = await mt.invitations.create(tenant_id, {
    email: "charlie@acme.com",
    grants: [{ role_id: editorRole.id, scope_id: projectBetaId }], // Scoped grant
  });

  console.log("Invites created for Alice (Global), Bob (Alpha), Charlie (Beta)");

  // ==========================================================================
  // 3. BOB LOGS IN (Restricted to Project Alpha)
  // ==========================================================================
  await supabase.auth.signInWithPassword({
    email: "bob@acme.com",
    password: "bob-password",
  });
  await mt.invitations.accept(bobInvite.token);

  // 3a. Bob checks UI permissions
  const bobCanInAlpha = await mt.can(tenant_id, "tasks.create", [projectAlphaId]);
  const bobCanInBeta = await mt.can(tenant_id, "tasks.create", [projectBetaId]);
  console.log(`Bob UI Checks -> Can create in Alpha: ${bobCanInAlpha}, in Beta: ${bobCanInBeta}`);
  // Result: bobCanInAlpha === true, bobCanInBeta === false!

  // 3b. Bob creates a task in Project Alpha (Allowed by RLS)
  const { data: bobTask, error: bobTaskError } = await supabase
    .from("tasks")
    .insert({
      tenant_id,
      project_id: projectAlphaId,
      title: "Implement iOS Login Screen",
    })
    .select()
    .single();

  if (bobTaskError) throw bobTaskError;
  console.log("Bob successfully created task in Alpha:", bobTask.id);

  // 3c. Bob attempts to create a task in Project Beta (DENIED BY RLS)
  const { error: hackError } = await supabase
    .from("tasks")
    .insert({
      tenant_id,
      project_id: projectBetaId, // Unauthorized scope!
      title: "Sneak into Beta Project",
    });

  console.log("Bob insertion into Beta rejected by RLS as expected:", hackError?.message);

  // ==========================================================================
  // 4. CHARLIE LOGS IN (Restricted to Project Beta)
  // ==========================================================================
  await supabase.auth.signInWithPassword({
    email: "charlie@acme.com",
    password: "charlie-password",
  });
  await mt.invitations.accept(charlieInvite.token);

  // 4a. Charlie queries all tasks in the organization
  const { data: charlieVisibleTasks } = await supabase
    .from("tasks")
    .select("id, title, project_id")
    .eq("tenant_id", tenant_id);

  // Charlie CANNOT see Bob's Alpha task! He only sees Beta tasks.
  console.log("Charlie sees tasks:", charlieVisibleTasks);

  // ==========================================================================
  // 5. ALICE LOGS IN (Tenant-Wide Manager)
  // ==========================================================================
  await supabase.auth.signInWithPassword({
    email: "alice@acme.com",
    password: "alice-password",
  });
  await mt.invitations.accept(aliceInvite.token);

  // Alice sees all tasks across BOTH Project Alpha and Project Beta
  const { data: aliceVisibleTasks } = await supabase
    .from("tasks")
    .select("id, title, project_id")
    .eq("tenant_id", tenant_id);

  console.log(`Alice (Manager) sees ALL ${aliceVisibleTasks?.length} tasks across both projects!`);
}

main().catch(console.error);
