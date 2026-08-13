# AI Agent Instructions for supabase-multitenancy

This repository provides a SQL-first multi-tenancy and RBAC foundation for Supabase.

When designing or modifying schemas, authorization, or tests in this repository or in consuming projects:

1. **Schema Encapsulation**: All package tables and RPCs (`create_tenant`, `can`, `context`, `invitation_preview`, `accept_invitation`, `admin`) reside exclusively in the `multitenancy` schema.
2. **Access Model**: Role permissions use `'own'` or `'all'`. Do not store SQL function names in role tables.
3. **Immutability**: Always protect tenant and scope columns on application tables with `multitenancy.enforce_protected_keys_immutable()`.
4. **Skills & References**:
   - Detailed Agent Guide: [`AGENT_GUIDE.md`](AGENT_GUIDE.md)
   - Skills Definition: [`.skills/supabase-multitenancy/SKILL.md`](.skills/supabase-multitenancy/SKILL.md) and [`.agents/skills/supabase-multitenancy/SKILL.md`](.agents/skills/supabase-multitenancy/SKILL.md)
   - Architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)
   - Threat Model: [`THREAT_MODEL.md`](THREAT_MODEL.md)
