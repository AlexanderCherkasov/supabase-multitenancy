from typing import Any, Dict, List, Optional, Protocol, TypeVar, cast

from .errors import map_database_error, unwrap_envelope
from .types import (
    AuditEvent,
    ContextSection,
    Grant,
    InvitationPreview,
    InvitationSummary,
    Membership,
    Permission,
    Role,
    Scope,
)

T = TypeVar("T")


class _Response(Protocol):
    data: Any


class _RpcBuilder(Protocol):
    def execute(self) -> _Response: ...


class SupabaseRpcClient(Protocol):
    def rpc(self, function_name: str, params: Dict[str, Any]) -> _RpcBuilder: ...


class MultitenancyClient:
    """Synchronous, user-session client for the package's public RPCs in the multitenancy schema."""

    def __init__(self, supabase: Any, *, schema: str = "multitenancy"):
        self._supabase = supabase.schema(schema) if hasattr(supabase, "schema") and callable(supabase.schema) else supabase
        self._schema = schema
        self.tenants = TenantsApi(self)
        self.permissions = PermissionsApi(self)
        self.roles = RolesApi(self)
        self.scopes = ScopesApi(self)
        self.members = MembersApi(self)
        self.invitations = InvitationsApi(self)
        self.audit = AuditApi(self)

    def _rpc(self, function_name: str, params: Dict[str, Any]) -> Any:
        try:
            response = self._supabase.rpc(function_name, params).execute()
        except Exception as error:
            raise map_database_error(error) from error
        return unwrap_envelope(response.data, function_name)

    def create_tenant(self, *, slug: str, name: str) -> Dict[str, str]:
        return cast(Dict[str, str], self._rpc("create_tenant", {"p_slug": slug, "p_name": name}))

    def context(
        self,
        tenant_id: str,
        section: ContextSection,
        *,
        cursor: Optional[str] = None,
        limit: int = 50,
    ) -> Any:
        return self._rpc(
            "context",
            {"p_tenant_id": tenant_id, "p_section": section, "p_cursor": cursor, "p_limit": limit},
        )

    def admin(self, tenant_id: str, command: str, payload: Dict[str, Any]) -> Any:
        if command.startswith("role."):
            raise ValueError("Role definitions are DBA-managed and cannot be mutated through the SDK")
        return self._rpc(
            "admin",
            {"p_tenant_id": tenant_id, "p_command": command, "p_payload": payload},
        )

    def can(self, tenant_id: str, permission: str, scope_ids: Optional[List[str]] = None) -> bool:
        result = self._rpc(
            "can",
            {"p_tenant_id": tenant_id, "p_permission": permission, "p_scope_ids": scope_ids},
        )
        return bool(result["allowed"])


class TenantsApi:
    def __init__(self, client: MultitenancyClient): self._client = client

    def get_self(self, tenant_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.context(tenant_id, "self"))

    def update(self, tenant_id: str, *, name: Optional[str] = None, slug: Optional[str] = None) -> Dict[str, Any]:
        payload = {key: value for key, value in {"name": name, "slug": slug}.items() if value is not None}
        return cast(Dict[str, Any], self._client.admin(tenant_id, "tenant.update", payload))

    def deactivate(self, tenant_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "tenant.deactivate", {}))

    def reactivate(self, tenant_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "tenant.reactivate", {}))

    def transfer_ownership(self, tenant_id: str, new_owner_user_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "tenant.transfer_ownership", {"new_owner_user_id": new_owner_user_id}))


class PermissionsApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[Permission]:
        return cast(List[Permission], self._client.context(tenant_id, "permissions", limit=limit))


class RolesApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[Role]:
        return cast(List[Role], self._client.context(tenant_id, "roles", limit=limit))


class ScopesApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[Scope]:
        return cast(List[Scope], self._client.context(tenant_id, "scopes", limit=limit))
    def create(self, tenant_id: str, *, kind: str, key: str, name: str, metadata: Optional[Dict[str, Any]] = None) -> Scope:
        return cast(Scope, self._client.admin(tenant_id, "scope.create", {"kind": kind, "key": key, "name": name, "metadata": metadata or {}}))
    def update(self, tenant_id: str, scope_id: str, *, name: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> Scope:
        payload = {key: value for key, value in {"scope_id": scope_id, "name": name, "metadata": metadata}.items() if value is not None}
        return cast(Scope, self._client.admin(tenant_id, "scope.update", payload))
    def remove(self, tenant_id: str, scope_id: str) -> Dict[str, bool]:
        return cast(Dict[str, bool], self._client.admin(tenant_id, "scope.delete", {"scope_id": scope_id}))


class MembersApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[Membership]:
        return cast(List[Membership], self._client.context(tenant_id, "members", limit=limit))
    def set_grants(self, tenant_id: str, membership_id: str, grants: List[Grant]) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "member.set_grants", {"membership_id": membership_id, "grants": grants}))
    def suspend(self, tenant_id: str, membership_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "member.suspend", {"membership_id": membership_id}))
    def reactivate(self, tenant_id: str, membership_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "member.reactivate", {"membership_id": membership_id}))
    def remove(self, tenant_id: str, membership_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "member.remove", {"membership_id": membership_id}))


class InvitationsApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[InvitationSummary]:
        return cast(List[InvitationSummary], self._client.context(tenant_id, "invitations", limit=limit))
    def create(self, tenant_id: str, *, email: str, grants: List[Grant]) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "invitation.create", {"email": email, "grants": grants}))
    def resend(self, tenant_id: str, invitation_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "invitation.resend", {"invitation_id": invitation_id}))
    def revoke(self, tenant_id: str, invitation_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._client.admin(tenant_id, "invitation.revoke", {"invitation_id": invitation_id}))
    def preview(self, token: str) -> InvitationPreview:
        return cast(InvitationPreview, self._client._rpc("invitation_preview", {"p_token": token}))
    def accept(self, token: str) -> Dict[str, str]:
        return cast(Dict[str, str], self._client._rpc("accept_invitation", {"p_token": token}))


class AuditApi:
    def __init__(self, client: MultitenancyClient): self._client = client
    def list(self, tenant_id: str, *, limit: int = 50) -> List[AuditEvent]:
        return cast(List[AuditEvent], self._client.context(tenant_id, "audit", limit=limit))
