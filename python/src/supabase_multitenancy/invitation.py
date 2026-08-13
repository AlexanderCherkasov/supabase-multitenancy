from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def build_accept_url(base_url: str, token: str) -> str:
    """Return an accept URL without logging or persisting the raw token."""
    scheme, netloc, path, query, fragment = urlsplit(base_url)
    params = dict(parse_qsl(query, keep_blank_values=True))
    params["token"] = token
    return urlunsplit((scheme, netloc, path, urlencode(params), fragment))


def redact_token(token: Optional[str]) -> str:
    """Safe value for diagnostics; never returns token material."""
    return "[redacted]" if token else "[missing]"
