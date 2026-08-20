# 🤝 Custom Predicates & Document Collaborators Example

This example demonstrates how to extend the **`own`** access level with application-specific custom row predicates, such as **document-level sharing and collaborators**.

---

## The Concept: `own` is Defined by the Application

In `supabase-multitenancy`:
- The core engine evaluates permissions and tenant/scope hierarchy to determine your live access level: **`none`**, **`own`**, or **`all`**.
- When `access_level = 'all'`, the user can access **all** rows in the tenant / scope.
- When `access_level = 'own'`, the **application RLS policy** decides what constitutes ownership:
  1. Direct authoring (`author_id = auth.uid()`)
  2. Direct assignment (`assignee_id = auth.uid()`)
  3. **Explicit item sharing (`is_document_collaborator(id, auth.uid())`)**

This architecture keeps the database core secure and immutable, while giving your application full freedom to implement custom sharing tables and predicates.

---

## 📁 Files in this Example

1. [`01_schema_and_collaborators.sql`](01_schema_and_collaborators.sql): Creates `public.documents` and `public.document_collaborators`.
2. [`02_custom_predicate_and_rls.sql`](02_custom_predicate_and_rls.sql): Defines the `is_document_collaborator` `SECURITY INVOKER` function and attaches RLS policies.
3. [`03_collaborators_workflow.ts`](03_collaborators_workflow.ts): End-to-end TypeScript workflow showing how an author shares a document with a teammate.

---

## 🔒 Security Best Practice: `SECURITY INVOKER`

Always define custom predicate functions as `SECURITY INVOKER`:

```sql
create or replace function public.is_document_collaborator(
  p_document_id uuid,
  p_user_id uuid,
  p_required_level text default 'view'
)
returns boolean
language sql
stable
security invoker -- Runs with the permissions of the calling user
set search_path = ''
as $$
  select exists (
    select 1
    from public.document_collaborators dc
    where dc.document_id = p_document_id
      and dc.user_id = p_user_id
      and (
        p_required_level = 'view'
        or dc.permission_level = 'edit'
      )
  );
$$;
```
