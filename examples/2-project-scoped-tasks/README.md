# 🎯 Project Scopes & Isolation Setup

This example demonstrates complete **Scope Restriction and Isolation** across multiple projects inside a single organization.

---

## 🏢 The Architecture

```
                       ┌───────────────────────────────┐
                       │          Acme Corp            │
                       │         (tenant_id)           │
                       └──────────────┬────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
        ┌────────▼────────┐                       ┌────────▼────────┐
        │  Project Alpha  │                       │   Project Beta  │
        │   (scope_id)    │                       │   (scope_id)    │
        └────────┬────────┘                       └────────┬────────┘
                 │                                         │
       ┌─────────▼─────────┐                     ┌─────────▼─────────┐
       │ Tasks (Bob only)  │                     │ Tasks (Charlie)   │
       └───────────────────┘                     └───────────────────┘
```

### Access Matrix

| User | Role | Scope Grant | Can Access Project Alpha? | Can Access Project Beta? |
| :--- | :--- | :--- | :---: | :---: |
| **Alice** | `task_manager` | `scope_id: null` *(Global)* | ✅ All Tasks | ✅ All Tasks |
| **Bob** | `task_editor` | `scope_id: alpha_id` *(Scoped)* | ✅ Own Tasks | ❌ Forbidden (0 rows) |
| **Charlie** | `task_editor` | `scope_id: beta_id` *(Scoped)* | ❌ Forbidden (0 rows) | ✅ Own Tasks |

---

## 📁 Files in this Example

1. [`01_permissions_and_roles.sql`](file:///Users/alexander/dev/supabase-multitenancy/examples/2-project-scoped-tasks/01_permissions_and_roles.sql): Declares permissions and roles (`task_viewer`, `task_editor`, `task_manager`).
2. [`02_tasks_table_and_rls.sql`](file:///Users/alexander/dev/supabase-multitenancy/examples/2-project-scoped-tasks/02_tasks_table_and_rls.sql): Table `tasks` with composite foreign key and RLS policies passing `array[project_id]`.
3. [`workflow_scoped_tasks.ts`](file:///Users/alexander/dev/supabase-multitenancy/examples/2-project-scoped-tasks/workflow_scoped_tasks.ts): End-to-end runnable script demonstrating multi-user scope isolation.
