# GitHub Copilot & OpenAI Codex Instructions for supabase-multitenancy

When generating code, SQL migrations, or architecture for multi-tenant applications using `supabase-multitenancy`:

1. **Zero Public Schema Pollution**:
   - Package tables and implementation routines live strictly in private schema `multitenancy`; client RPCs and RLS helpers use exposed `api` wrappers.
   - Never expose `multitenancy` through the Data API or generate package objects in `public`.

2. **DBA-Managed Roles & Access Levels**:
   - Permissions are registered via `insert into multitenancy.permissions (key, description)`.
   - Roles map permissions strictly to access levels `'own'` or `'all'`.
   - Never store SQL function names in role table columns.

3. **Key Immutability on Business Tables**:
   - Business tables must reference `tenant_id` and optional `scope_id` with composite FK `(tenant_id, scope_id) references multitenancy.scopes(tenant_id, id)`.
   - Always attach the key protection trigger: `api.enforce_protected_keys_immutable()`.

4. **Canonical RLS Pattern**:
   ```sql
   create policy "resources_select" on public.resources
   for select to authenticated
   using (
     case api.access_level(tenant_id, 'resources.read', array[scope_id])
       when 'all' then true
       when 'own' then author_id = auth.uid()
       else false
     end
   );
   ```

5. **Client SDK**:
   - Use `createMultitenancyClient(supabase)` from `supabase-multitenancy`.
   - Use `await mt.can(tenant_id, 'resources.delete', [scope_id])` for UI action guards; the SDK defaults to the `api` schema.
   - For detailed templates, refer to `AGENT_GUIDE.md` and `.skills/supabase-multitenancy/SKILL.md`.
