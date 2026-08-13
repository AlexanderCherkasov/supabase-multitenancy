export type TenantId = string;
export type ScopeId = string;
export type AccessLevel = "own" | "all";
export type MembershipStatus = "active" | "suspended" | "removed";

export interface Tenant {
  id: TenantId;
  slug: string;
  name: string;
  owner_user_id: string;
  is_active: boolean;
}

export interface Scope {
  id: ScopeId;
  tenant_id?: TenantId;
  kind: string;
  key: string;
  name: string;
  metadata?: Record<string, unknown>;
}

export interface Permission {
  key: string;
  origin: "package" | "application";
  is_deprecated: boolean;
}

export interface RolePermission {
  key: string;
  access_level: AccessLevel;
}

export interface Role {
  id: string;
  key: string;
  name: string;
  description?: string | null;
  permissions?: RolePermission[] | null;
}

export interface Grant {
  role_id: string;
  scope_id?: string | null;
}

export interface Membership {
  id: string;
  user_id: string;
  status: MembershipStatus;
  display_name?: string | null;
  grants?: Grant[] | null;
}

export interface InvitationSummary {
  id: string;
  email: string;
  email_normalized: string;
  expires_at: string;
  revoked_at: string | null;
  accepted_at: string | null;
  created_at: string;
}

export interface InvitationPreviewGrant {
  role: string;
  scope_id?: string | null;
}

export interface InvitationPreview {
  tenant_id: string;
  tenant_name: string;
  email_masked: string;
  expires_at: string;
  grants: InvitationPreviewGrant[];
  valid: true;
}

export interface AuditEvent {
  id: string;
  actor_user_id: string | null;
  command: string;
  entity_type: string | null;
  entity_id: string | null;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface SelfContext {
  tenant: Tenant;
  membership: Pick<Membership, "id" | "status"> | null;
  is_owner: boolean;
}

export interface ContextDataMap {
  self: SelfContext;
  permissions: Permission[];
  scopes: Scope[];
  roles: Role[];
  members: Membership[];
  invitations: InvitationSummary[];
  audit: AuditEvent[];
}

export type ContextSection = keyof ContextDataMap;

export type PermissionKey<AppPermission extends string = string> =
  | `multitenancy.${string}`
  | AppPermission;

export type AdminCommand =
  | { command: "tenant.update"; payload: { name?: string; slug?: string } }
  | { command: "tenant.deactivate"; payload: Record<string, never> }
  | { command: "tenant.reactivate"; payload: Record<string, never> }
  | { command: "tenant.transfer_ownership"; payload: { new_owner_user_id: string } }
  | { command: "scope.create"; payload: { kind: string; key: string; name: string; metadata?: Record<string, unknown> } }
  | { command: "scope.update"; payload: { scope_id: string; name?: string; metadata?: Record<string, unknown> } }
  | { command: "scope.delete"; payload: { scope_id: string } }
  | { command: "member.set_grants"; payload: { membership_id: string; grants: Grant[] } }
  | { command: "member.suspend"; payload: { membership_id: string } }
  | { command: "member.reactivate"; payload: { membership_id: string } }
  | { command: "member.remove"; payload: { membership_id: string } }
  | { command: "invitation.create"; payload: { email: string; grants: Grant[] } }
  | { command: "invitation.resend"; payload: { invitation_id: string } }
  | { command: "invitation.revoke"; payload: { invitation_id: string } };

export interface RpcEnvelope<T> {
  api_version: 1;
  data: T;
}
