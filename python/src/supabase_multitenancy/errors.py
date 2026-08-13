from enum import Enum
from typing import Any, Optional


class ErrorCode(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    INVALID_INPUT = "INVALID_INPUT"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    TOKEN_ACCEPTED = "TOKEN_ACCEPTED"
    EMAIL_MISMATCH = "EMAIL_MISMATCH"
    LAST_OWNER = "LAST_OWNER"
    ROLE_ESCALATION = "ROLE_ESCALATION"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    UNKNOWN = "UNKNOWN"


class MultitenancyError(RuntimeError):
    def __init__(self, code: ErrorCode, message: str, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.code = code
        self.cause = cause


_PREFIXES = tuple(code for code in ErrorCode if code not in (ErrorCode.UNKNOWN,))
_PG_CODES = {
    "28000": ErrorCode.UNAUTHENTICATED,
    "42501": ErrorCode.FORBIDDEN,
    "42704": ErrorCode.NOT_FOUND,
    "23505": ErrorCode.CONFLICT,
    "22P02": ErrorCode.INVALID_INPUT,
}


def map_database_error(error: BaseException) -> MultitenancyError:
    message = str(getattr(error, "message", None) or error)
    pg_code = str(getattr(error, "code", "") or "")
    for code in _PREFIXES:
        if message.startswith(code.value):
            return MultitenancyError(code, message, error)
    return MultitenancyError(_PG_CODES.get(pg_code, ErrorCode.UNKNOWN), message, error)


def unwrap_envelope(value: Any, function_name: str) -> Any:
    if not isinstance(value, dict) or "api_version" not in value:
        raise MultitenancyError(ErrorCode.VERSION_MISMATCH, f"Missing api_version in {function_name} response")
    if value["api_version"] != 1:
        raise MultitenancyError(
            ErrorCode.VERSION_MISMATCH,
            f"Unsupported api_version {value['api_version']}, expected 1",
        )
    return value.get("data")
