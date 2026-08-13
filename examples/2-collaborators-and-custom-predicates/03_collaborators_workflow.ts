import { createClient } from "@supabase/supabase-js";
import { createMultitenancyClient } from "supabase-multitenancy";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL!;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY!;

  const supabase = createClient(supabaseUrl, supabaseAnonKey);
  const mt = createMultitenancyClient(supabase);

  // 1. Sign in as Tenant Owner / Author (User A)
  await supabase.auth.signInWithPassword({
    email: "author_alex@example.com",
    password: "secure-password",
  });

  const { tenant_id } = await mt.createTenant({
    slug: "design-studio",
    name: "Design Studio",
  });

  // 2. Author creates a private document
  const { data: document, error: docError } = await supabase
    .from("documents")
    .insert({
      tenant_id,
      title: "Design System RFC",
      content: "Initial draft of token specifications.",
    })
    .select()
    .single();

  if (docError) throw docError;
  console.log("Author created document:", document.id);

  // 3. User B (Sarah) is a team member with 'editor' role (access_level = 'own')
  const sarahUserId = "00000000-0000-0000-0000-000000000002"; // Sarah's auth.users id

  // Initially, Sarah cannot see or edit Alex's document because author_id is Alex!
  // 4. Alex invites Sarah to collaborate directly on this document:
  const { error: shareError } = await supabase
    .from("document_collaborators")
    .insert({
      tenant_id,
      document_id: document.id,
      user_id: sarahUserId,
      permission_level: "edit", // 'view' or 'edit'
    });

  if (shareError) throw shareError;
  console.log(`Shared document ${document.id} with collaborator ${sarahUserId}`);

  // --------------------------------------------------------------------------
  // SWITCH USER: Sarah logs in
  // --------------------------------------------------------------------------
  await supabase.auth.signInWithPassword({
    email: "sarah@example.com",
    password: "sarah-password",
  });

  // 5. Sarah queries documents -> Through the custom predicate `is_document_collaborator`,
  // the RLS policy dynamically includes documents where she is a registered collaborator!
  const { data: sarahVisibleDocs } = await supabase
    .from("documents")
    .select("id, title, content")
    .eq("tenant_id", tenant_id);

  console.log("Sarah sees shared document:", sarahVisibleDocs);

  // 6. Sarah updates the shared document content:
  const { error: updateError } = await supabase
    .from("documents")
    .update({
      content: "Updated token specifications with dark mode palette.",
    })
    .eq("id", document.id);

  if (updateError) {
    console.error("Sarah update failed:", updateError);
  } else {
    console.log("Sarah successfully updated the shared document!");
  }
}

main().catch(console.error);
