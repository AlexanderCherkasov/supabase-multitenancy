import type { SupabaseClient } from "@supabase/supabase-js";
import { assertApiVersion, mapPostgresError, MultitenancyError } from "./errors.js";
import type {
  AdminCommand,
  AuditEvent,
  ContextDataMap,
  ContextSection,
  Grant,
  InvitationPreview,
  InvitationSummary,
  Membership,
  Permission,
  PermissionKey,
  Role,
  RpcEnvelope,
  Scope,
  Tenant,
} from "./types.js";

export interface ContextOptions {
  cursor?: string | null;
  limit?: number;
}

export interface ClientOptions {
  schema?: string;
}

export function createMultitenancyClient<AppPermission extends string = string>(
  supabase: SupabaseClient,
  clientOptions?: ClientOptions
) {
  const schemaName = clientOptions?.schema ?? "multitenancy";
  const api = typeof supabase.schema === "function" ? supabase.schema(schemaName) : supabase;

  async function rpc<T>(fn: string, params: Record<string, unknown>): Promise<T> {
    const { data, error } = await api.rpc(fn, params as never);
    if (error) throw mapPostgresError(error as { message?: string; code?: string });
    const envelope = data as RpcEnvelope<T> | null;
    if (!envelope || typeof envelope !== "object" || !("api_version" in envelope)) {
      throw new MultitenancyError("VERSION_MISMATCH", `Missing api_version in ${fn} response`);
    }
    assertApiVersion(envelope);
    return envelope.data;
  }

  async function context<S extends ContextSection>(
    tenantId: string,
    section: S,
    options: ContextOptions = {}
  ): Promise<ContextDataMap[S]> {
    return rpc<ContextDataMap[S]>("context", {
      p_tenant_id: tenantId,
      p_section: section,
      p_cursor: options.cursor ?? null,
      p_limit: options.limit ?? 50,
    });
  }

  async function admin<T = unknown>(tenantId: string, command: AdminCommand): Promise<T> {
    return rpc<T>("admin", {
      p_tenant_id: tenantId,
      p_command: command.command,
      p_payload: command.payload,
    });
  }

  return {
    context,
    admin,

    async createTenant(input: { slug: string; name: string }): Promise<{ tenant_id: string; slug: string; name: string }> {
      return rpc("create_tenant", { p_slug: input.slug, p_name: input.name });
    },

    tenants: {
      async getSelf(tenantId: string) { return context(tenantId, "self"); },
      async update(tenantId: string, patch: { name?: string; slug?: string }): Promise<Pick<Tenant, "id" | "slug" | "name">> {
        return admin(tenantId, { command: "tenant.update", payload: patch });
      },
      async deactivate(tenantId: string): Promise<{ tenant_id: string; is_active: false }> {
        return admin(tenantId, { command: "tenant.deactivate", payload: {} });
      },
      async reactivate(tenantId: string): Promise<{ tenant_id: string; is_active: true }> {
        return admin(tenantId, { command: "tenant.reactivate", payload: {} });
      },
      async transferOwnership(tenantId: string, newOwnerUserId: string): Promise<{ tenant_id: string; owner_user_id: string }> {
        return admin(tenantId, { command: "tenant.transfer_ownership", payload: { new_owner_user_id: newOwnerUserId } });
      },
    },

    permissions: {
      async list(tenantId: string, options?: ContextOptions): Promise<Permission[]> {
        return context(tenantId, "permissions", options);
      },
    },

    roles: {
      // Read-only by design. DBA migrations own role definitions.
      async list(tenantId: string, options?: ContextOptions): Promise<Role[]> {
        return context(tenantId, "roles", options);
      },
    },

    scopes: {
      async list(tenantId: string, options?: ContextOptions): Promise<Scope[]> {
        return context(tenantId, "scopes", options);
      },
      async create(tenantId: string, input: { kind: string; key: string; name: string; metadata?: Record<string, unknown> }): Promise<Scope> {
        return admin(tenantId, { command: "scope.create", payload: input });
      },
      async update(tenantId: string, scopeId: string, patch: { name?: string; metadata?: Record<string, unknown> }): Promise<Scope> {
        return admin(tenantId, { command: "scope.update", payload: { scope_id: scopeId, ...patch } });
      },
      async remove(tenantId: string, scopeId: string): Promise<{ deleted: boolean }> {
        return admin(tenantId, { command: "scope.delete", payload: { scope_id: scopeId } });
      },
    },

    members: {
      async list(tenantId: string, options?: ContextOptions): Promise<Membership[]> {
        return context(tenantId, "members", options);
      },
      async setGrants(tenantId: string, membershipId: string, grants: Grant[]) {
        return admin<{ membership_id: string; grants: Grant[] }>(tenantId, {
          command: "member.set_grants",
          payload: { membership_id: membershipId, grants },
        });
      },
      async suspend(tenantId: string, membershipId: string) {
        return admin<{ membership_id: string; status: "suspended" }>(tenantId, { command: "member.suspend", payload: { membership_id: membershipId } });
      },
      async reactivate(tenantId: string, membershipId: string) {
        return admin<{ membership_id: string; status: "active" }>(tenantId, { command: "member.reactivate", payload: { membership_id: membershipId } });
      },
      async remove(tenantId: string, membershipId: string) {
        return admin<{ membership_id: string; status: "removed" }>(tenantId, { command: "member.remove", payload: { membership_id: membershipId } });
      },
    },

    invitations: {
      async list(tenantId: string, options?: ContextOptions): Promise<InvitationSummary[]> {
        return context(tenantId, "invitations", options);
      },
      async create(tenantId: string, input: { email: string; grants: Grant[] }): Promise<{ invitation_id: string; token: string; expires_at: string }> {
        return admin(tenantId, { command: "invitation.create", payload: input });
      },
      async resend(tenantId: string, invitationId: string): Promise<{ invitation_id: string; token: string; expires_at: string }> {
        return admin(tenantId, { command: "invitation.resend", payload: { invitation_id: invitationId } });
      },
      async revoke(tenantId: string, invitationId: string): Promise<{ invitation_id: string; revoked: boolean }> {
        return admin(tenantId, { command: "invitation.revoke", payload: { invitation_id: invitationId } });
      },
      async preview(token: string): Promise<InvitationPreview> {
        return rpc("invitation_preview", { p_token: token });
      },
      async accept(token: string): Promise<{ tenant_id: string; membership_id: string }> {
        return rpc("accept_invitation", { p_token: token });
      },
    },

    audit: {
      async list(tenantId: string, options?: ContextOptions): Promise<AuditEvent[]> {
        return context(tenantId, "audit", options);
      },
    },

    async can(tenantId: string, permission: PermissionKey<AppPermission>, scopeIds?: string[] | null): Promise<boolean> {
      const data = await rpc<{ allowed: boolean }>("can", {
        p_tenant_id: tenantId,
        p_permission: permission,
        p_scope_ids: scopeIds ?? null,
      });
      return data.allowed;
    },
  };
}

export type MultitenancyClient<AppPermission extends string = string> = ReturnType<typeof createMultitenancyClient<AppPermission>>;
