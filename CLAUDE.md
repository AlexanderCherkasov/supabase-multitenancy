# Claude Code Instructions for supabase-multitenancy

## Overview
This repository provides a SQL-first multi-tenancy and RBAC foundation for Supabase.

## Commands
- Build SQL install artifact: `npm run build:sql`
- Build TypeScript: `npm run build`
- Run TypeScript unit tests: `npm test`
- Run Python unit tests: `PYTHONPATH=python/src python3 -m unittest python/tests/test_client.py`

## Architecture Rules
1. **Schema**: All package tables and routines (`create_tenant`, `can`, `context`, `invitation_preview`, `accept_invitation`, `admin`) reside in the `multitenancy` schema.
2. **Access Model**: Permissions are mapped to roles using `'own'` or `'all'`.
3. **Immutability**: Always protect tenant and scope foreign keys with `multitenancy.enforce_protected_keys_immutable()`.
4. **Reference**: See `AGENT_GUIDE.md` and `.skills/supabase-multitenancy/SKILL.md` for RLS patterns and workflows.
