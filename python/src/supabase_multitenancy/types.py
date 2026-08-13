from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

AccessLevel = Literal["own", "all"]
MembershipStatus = Literal["active", "suspended", "removed"]
ContextSection = Literal["self", "permissions", "scopes", "roles", "members", "invitations", "audit"]


class Tenant(TypedDict):
    id: str
    slug: str
    name: str
    owner_user_id: str
    is_active: bool


class Scope(TypedDict, total=False):
    id: str
    tenant_id: str
    kind: str
    key: str
    name: str
    metadata: Dict[str, Any]


class Permission(TypedDict):
    key: str
    origin: Literal["package", "application"]
    is_deprecated: bool


class RolePermission(TypedDict):
    key: str
    access_level: AccessLevel


class Role(TypedDict, total=False):
    id: str
    key: str
    name: str
    description: Optional[str]
    permissions: Optional[List[RolePermission]]


class Grant(TypedDict, total=False):
    role_id: str
    scope_id: Optional[str]


class Membership(TypedDict, total=False):
    id: str
    user_id: str
    status: MembershipStatus
    display_name: Optional[str]
    grants: Optional[List[Grant]]


class InvitationSummary(TypedDict):
    id: str
    email: str
    email_normalized: str
    expires_at: str
    revoked_at: Optional[str]
    accepted_at: Optional[str]
    created_at: str


class InvitationPreviewGrant(TypedDict, total=False):
    role: str
    scope_id: Optional[str]


class InvitationPreview(TypedDict):
    tenant_id: str
    tenant_name: str
    email_masked: str
    expires_at: str
    grants: List[InvitationPreviewGrant]
    valid: bool


class AuditEvent(TypedDict, total=False):
    id: str
    actor_user_id: Optional[str]
    command: str
    entity_type: Optional[str]
    entity_id: Optional[str]
    payload: Dict[str, Any]
    created_at: str


JsonValue = Union[None, bool, int, float, str, List["JsonValue"], Dict[str, "JsonValue"]]
