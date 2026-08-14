# GitHub Copilot & OpenAI Codex Instructions for supabase-multitenancy

When generating code, SQL migrations, or architecture for multi-tenant applications using `supabase-multitenancy`:

1. **Zero Public Schema Pollution**:
   - All package routines (`create_tenant`, `can`, `context`, `invitation_preview`, `accept_invitation`, `admin`) and tables live strictly in schema `multitenancy`.
   - Never generate package functions or tables in the `public` schema.

2. **DBA-Managed Roles & Access Levels**:
   - Permissions are registered via `insert into multitenancy.permissions (key, description)`.
   - Roles map permissions strictly to access levels `'own'` or `'all'`.
   - Never store SQL function names in role table columns.

3. **Key Immutability on Business Tables**:
   - Business tables must reference `tenant_id` and optional `scope_id` with composite FK `(tenant_id, scope_id) references multitenancy.scopes(tenant_id, id)`.
   - Always attach the key protection trigger: `multitenancy.enforce_protected_keys_immutable()`.

4. **Canonical RLS Pattern**:
   ```sql
   create policy "resources_select" on public.resources
   for select to authenticated
   using (
     case multitenancy.access_level(tenant_id, 'resources.read', array[scope_id])
       when 'all' then true
       when 'own' then author_id = auth.uid()
       else false
     end
   );
   ```

5. **Client SDK**:
   - Use `createMultitenancyClient(supabase)` from `supabase-multitenancy`.
   - Use `await mt.can(tenant_id, 'resources.delete', [scope_id])` for UI action guards.
   - For detailed templates, refer to `AGENT_GUIDE.md` and `.skills/supabase-multitenancy/SKILL.md`.
