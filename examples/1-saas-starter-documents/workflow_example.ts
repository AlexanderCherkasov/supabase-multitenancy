import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-multitenancy";

// Define your application's permission union for full TypeScript autocompletion
type AppPermission =
  | "documents.read"
  | "documents.create"
  | "documents.update"
  | "documents.delete";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL!;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;

  // 1. Initialize Supabase Client for the current authenticated user
  const supabase = createClient(supabaseUrl, supabaseAnonKey);
  const mt = createMultitenancyClient<AppPermission>(supabase);

  // 2. Authenticate (e.g. Sign in as Owner)
  await supabase.auth.signInWithPassword({
    email: "owner@acme.com",
    password: "secure-password",
  });

  // 3. Create a Tenant Organization
  const { tenant_id } = await mt.createTenant({
    slug: "acme-corp",
    name: "Acme Corporation",
  });
  console.log("Tenant created:", tenant_id);

  // 4. Create a Project Scope (e.g. "Marketing Project")
  const { scope_id: marketingScopeId } = await mt.scopes.create(tenant_id, {
    kind: "project",
    key: "marketing-2026",
    name: "Marketing 2026",
  });
  console.log("Project Scope created:", marketingScopeId);

  // 5. Fetch available DBA-defined Roles
  const roles = await mt.roles.list(tenant_id);
  const editorRole = roles.find((r) => r.key === "editor")!;
  const managerRole = roles.find((r) => r.key === "manager")!;

  // 6. Invite Alice as 'editor' specifically inside the Marketing Project Scope
  const aliceInvite = await mt.invitations.create(tenant_id, {
    email: "alice@acme.com",
    grants: [
      {
        role_id: editorRole.id,
        scope_id: marketingScopeId, // scoped to Marketing only!
      },
    ],
  });
  console.log("Invite created for Alice. Token:", aliceInvite.token);

  // 7. Invite Bob as 'manager' at Tenant Root (no scope_id = tenant-wide access)
  const bobInvite = await mt.invitations.create(tenant_id, {
    email: "bob@acme.com",
    grants: [
      {
        role_id: managerRole.id, // tenant-wide manager
      },
    ],
  });
  console.log("Invite created for Bob. Token:", bobInvite.token);

  // --------------------------------------------------------------------------
  // SWITCH USER: Alice logs in and accepts the invitation
  // --------------------------------------------------------------------------
  await supabase.auth.signInWithPassword({
    email: "alice@acme.com",
    password: "alice-password",
  });

  // Preview invitation anonymously or while authenticated
  const preview = await mt.invitations.preview(aliceInvite.token);
  console.log(`Alice previewing invite for tenant "${preview.tenant_name}"`);

  // Accept the invitation
  await mt.invitations.accept(aliceInvite.token);
  console.log("Alice accepted invitation!");

  // 8. Alice checks her permissions for UI button rendering
  const canCreate = await mt.can(tenant_id, "documents.create", [marketingScopeId]);
  const canDelete = await mt.can(tenant_id, "documents.delete", [marketingScopeId]);
  console.log("Alice UI checks -> Can create:", canCreate, "Can delete:", canDelete);
  // canCreate === true, canDelete === false (editor role has no delete permission)

  // 9. Alice creates a document via standard Supabase PostgREST client
  const { data: doc, error: insertErr } = await supabase
    .from("documents")
    .insert({
      tenant_id,
      project_id: marketingScopeId,
      title: "Q3 Marketing Strategy",
      content: "Confidential roadmap for Q3.",
    })
    .select()
    .single();

  if (insertErr) throw insertErr;
  console.log("Alice created document:", doc.id);

  // 10. Alice reads documents -> RLS ensures she sees only her own rows!
  const { data: aliceDocs } = await supabase
    .from("documents")
    .select("*")
    .eq("tenant_id", tenant_id);
  console.log("Alice sees", aliceDocs?.length, "document(s)");

  // --------------------------------------------------------------------------
  // SWITCH USER: Bob logs in (Manager)
  // --------------------------------------------------------------------------
  await supabase.auth.signInWithPassword({
    email: "bob@acme.com",
    password: "bob-password",
  });
  await mt.invitations.accept(bobInvite.token);

  // Bob has 'all' access: he can see Alice's documents and edit/delete them!
  const { data: bobDocs } = await supabase
    .from("documents")
    .select("*")
    .eq("tenant_id", tenant_id);
  console.log("Bob (Manager) sees all", bobDocs?.length, "document(s)");

  // 11. Fetch live dashboard context (tenant info, scopes, members, audit events)
  const context = await mt.context(tenant_id, "self");
  console.log("Current user context:", context);
}

main().catch(console.error);
