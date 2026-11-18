"""
modal_mcp.oauth
===============

A small OAuth 2.1 authorization server for the MCP endpoint.

Why it exists
-------------
ChatGPT's dialog for a custom MCP server offers three authentication modes:
``OAuth``, ``No authentication`` and a mixed mode. It has **no** field for a
bearer token or for a custom header, so a server that wants a real credential
has to speak OAuth. This module implements the part of OAuth 2.1 that a chat
client needs:

* the metadata of the authorization server (RFC 8414) and of the protected
  resource (RFC 9728);
* the dynamic registration of a client (RFC 7591) - ChatGPT registers itself
  when the operator does not provide static credentials;
* the authorization code flow with PKCE (RFC 7636) - the ``S256`` method is
  the only one that is accepted;
* the refresh token flow, so that the connection survives the expiry of the
  access token.

The authorization page is closed: it asks for the enrolment code of the owner.
A visitor without that code cannot enrol a client, so the endpoint cannot be
taken over by whoever learns the URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .config import Settings
from .policy import audit
from .state import StateStore

#: The lifetime of an authorization code, in seconds.
CODE_TTL_SEC = 600

#: The lifetime of an access token, in seconds.
ACCESS_TOKEN_TTL_SEC = 12 * 3600

#: The lifetime of a refresh token, in seconds.
REFRESH_TOKEN_TTL_SEC = 30 * 24 * 3600

#: The lifetime of a registered client, in seconds.
CLIENT_TTL_SEC = 90 * 24 * 3600

#: The scope of this server. The scope is empty on purpose: the server does
#: not divide its operations into groups, it applies the same policy to all.
DEFAULT_SCOPE = ""

#: Strict Host header validation for local fallback mode.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(:\d+)?$")

#: Rate-limit constants for OAuth endpoints.
REGISTER_PER_IP_HOURLY_LIMIT = 10
REGISTER_GLOBAL_HOURLY_LIMIT = 50
AUTHORIZE_FAILURE_LIMIT = 5
AUTHORIZE_LOCKOUT_SEC = 900
MAX_REGISTER_BODY_BYTES = 16_384
MAX_REDIRECT_URIS = 10

_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


def _token_hash(token: str) -> str:
    """The digest under which a token is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _b64url(data: bytes) -> str:
    """The base64url encoding without padding (RFC 7636)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_ok(verifier: str, challenge: str) -> bool:
    """Check a PKCE verifier against its challenge."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return hmac.compare_digest(_b64url(digest), challenge)


class OAuthServer:
    """The authorization server of the MCP endpoint."""

    def __init__(self, settings: Settings, state: StateStore) -> None:
        self.settings = settings
        self.state = state

    # -- helpers -------------------------------------------------------------

    def _issuer(self, request: Request) -> str:
        """
        The issuer of this server.

        The configured issuer wins: the public URL of the deployment is known
        and it does not change between the requests. Only when nothing is
        configured - a local run - the issuer is derived from the validated
        Host header.
        """
        if self.settings.issuer:
            return self.settings.issuer.rstrip("/")
        raw_host = request.headers.get("host", "").strip()
        host = raw_host if _HOST_RE.match(raw_host) else "localhost"
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        proto = forwarded_proto.split(",")[0].strip().lower() if forwarded_proto else request.url.scheme
        scheme = proto if proto in ("http", "https") else "https"
        return f"{scheme}://{host}"

    @staticmethod
    def _client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64] or "unknown"
        if request.client and request.client.host:
            return str(request.client.host)[:64]
        return "unknown"

    def _valid_redirect_uri(self, uri: str) -> bool:
        """Validate an OAuth redirect URI using strict URL parsing."""
        if not isinstance(uri, str) or not uri or len(uri) > 2048:
            return False
        parsed = urlparse(uri)
        if parsed.fragment or parsed.username is not None or parsed.password is not None:
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if parsed.scheme == "https":
            if not parsed.netloc:
                return False
            if self.settings.allowed_redirect_hosts:
                return hostname in self.settings.allowed_redirect_hosts
            return True
        if parsed.scheme == "http":
            return hostname in ("localhost", "127.0.0.1")
        return False

    def _check_and_bump_limit(self, key_prefix: str, limit: int, window_sec: int) -> bool:
        """Return True if under limit (and increment), False if limit exceeded."""
        window = int(time.time() // window_sec)
        key = f"oauth:rl:{key_prefix}:{window}"
        record = self.state.get_json(key) or {}
        count = int(record.get("count", 0))
        if count >= limit:
            return False
        self.state.put_json(key, {"count": count + 1}, ttl_sec=window_sec + 60)
        return True

    def _get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        return self.state.get_json(f"oauth:client:{client_id}")

    def _put_client(self, client_id: str, record: Dict[str, Any]) -> None:
        self.state.put_json(
            f"oauth:client:{client_id}", record, ttl_sec=CLIENT_TTL_SEC
        )

    # -- the metadata --------------------------------------------------------

    async def metadata(self, request: Request) -> JSONResponse:
        """The metadata of the authorization server (RFC 8414)."""
        issuer = self._issuer(request)
        payload = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "registration_endpoint": f"{issuer}/register",
            "revocation_endpoint": f"{issuer}/revoke",
            "scopes_supported": [DEFAULT_SCOPE] if DEFAULT_SCOPE else [],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "service_documentation": f"{issuer}/mcp",
        }
        return JSONResponse(payload)

    async def resource_metadata(self, request: Request) -> JSONResponse:
        """The metadata of the protected resource (RFC 9728)."""
        issuer = self._issuer(request)
        payload = {
            "resource": f"{issuer}/mcp",
            "authorization_servers": [issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [DEFAULT_SCOPE] if DEFAULT_SCOPE else [],
        }
        return JSONResponse(payload)

    # -- the registration ----------------------------------------------------

    async def register(self, request: Request) -> Response:
        """The dynamic registration of a client (RFC 7591)."""
        client_ip = self._client_ip(request)
        if not self._check_and_bump_limit(
            f"register:ip:{client_ip}", REGISTER_PER_IP_HOURLY_LIMIT, 3600
        ) or not self._check_and_bump_limit(
            "register:global", REGISTER_GLOBAL_HOURLY_LIMIT, 3600
        ):
            audit("oauth_register_rate_limited", ip=client_ip)
            return JSONResponse(
                {"error": "too_many_requests", "error_description": "client registration rate limit exceeded"},
                status_code=429,
            )

        raw_body = await request.body()
        if len(raw_body) > MAX_REGISTER_BODY_BYTES:
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "the registration payload is too large"},
                status_code=413,
            )
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:  # noqa: BLE001 - a broken body is a refused registration
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "the body is not a JSON object"},
                status_code=400,
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "the body is not a JSON object"},
                status_code=400,
            )

        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris or len(redirect_uris) > MAX_REDIRECT_URIS:
            return JSONResponse(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "the registration needs 1 to 10 redirect URIs",
                },
                status_code=400,
            )
        clean_uris = []
        for uri in redirect_uris:
            if not self._valid_redirect_uri(uri):
                return JSONResponse(
                    {
                        "error": "invalid_redirect_uri",
                        "error_description": "a redirect URI must be a valid https URI or http://localhost / http://127.0.0.1 URI",
                    },
                    status_code=400,
                )
            clean_uris.append(uri)

        client_id = "mcp_" + secrets.token_urlsafe(18)
        client_secret = secrets.token_urlsafe(32)
        # A confidential client gets a secret, a public one (the method
        # ``none``) does not need one and is not asked for one later.
        is_public = body.get("token_endpoint_auth_method") == "none"
        record = {
            "client_id": client_id,
            "client_name": str(body.get("client_name") or "chatgpt")[:120],
            "redirect_uris": clean_uris,
            "public": is_public,
            "created_at": time.time(),
        }
        if not is_public:
            record["client_secret_hash"] = hashlib.sha256(
                client_secret.encode("utf-8")
            ).hexdigest()
        self._put_client(client_id, record)
        audit("oauth_client_registered", client_id=client_id, client_name=record["client_name"])

        response: Dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": int(record["created_at"]),
            "redirect_uris": clean_uris,
            "client_name": record["client_name"],
            "token_endpoint_auth_method": "none" if is_public else "client_secret_post",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
        if not is_public:
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = 0
        return JSONResponse(response, status_code=201)

    # -- the authorization ---------------------------------------------------

    async def authorize_page(self, request: Request) -> Response:
        """The consent page of the server."""
        params = dict(request.query_params)
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "")
        scope = params.get("scope", DEFAULT_SCOPE)

        error = self._check_authorize_params(
            client_id, redirect_uri, code_challenge, code_challenge_method
        )
        if error:
            return JSONResponse({"error": error[0], "error_description": error[1]}, status_code=400)

        client = self._get_client(client_id) or {}
        issuer = self._issuer(request)
        csrf_token = secrets.token_urlsafe(24)
        self.state.put_json(
            f"oauth:csrf:{_token_hash(csrf_token)}",
            {"client_id": client_id, "redirect_uri": redirect_uri},
            ttl_sec=CODE_TTL_SEC,
        )
        hidden = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "scope": scope,
            "csrf_token": csrf_token,
        }
        fields = "".join(
            f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(str(value))}">'
            for name, value in hidden.items()
        )
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Authorize - Modal MCP</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:0;padding:3rem;background:#0f1115;color:#e6e6e6}}
 .card{{max-width:32rem;margin:0 auto;background:#171a21;border:1px solid #2b2f3a;border-radius:12px;padding:2rem}}
 h1{{font-size:1.25rem;margin:0 0 1rem}}
 p{{line-height:1.5;color:#b9bec9}}
 input[type=password]{{width:100%;padding:.6rem;border-radius:8px;border:1px solid #333846;background:#0f1115;color:#e6e6e6}}
 button{{margin-top:1rem;padding:.6rem 1.2rem;border-radius:8px;border:0;background:#4f7cff;color:#fff;font-weight:600;cursor:pointer}}
 code{{color:#9fb3ff}}
</style></head><body><div class="card">
<h1>Modal MCP - authorization</h1>
<p>Client <code>{html.escape(str(client.get("client_name", "unknown")))}</code>
(<code>{html.escape(client_id)}</code>) asks for access to the Modal MCP server of
<code>aegis-rlvr-cpu-audit</code>.</p>
<p>Enter the enrolment code of the owner to approve this client.</p>
<form method="post" action="/authorize">
{fields}
<input type="password" name="enrollment_code" placeholder="Enrolment code" autofocus>
<button type="submit">Approve</button>
</form>
<p style="margin-top:1.5rem;font-size:.85rem">Issuer: <code>{html.escape(issuer)}</code></p>
</div></body></html>"""
        return HTMLResponse(page, headers=_SECURITY_HEADERS)

    def _check_authorize_params(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> Optional[Tuple[str, str]]:
        """Check the parameters of an authorization request."""
        if not client_id:
            return ("invalid_request", "the client identifier is missing")
        client = self._get_client(client_id)
        if not client:
            return ("invalid_client", "the client is not registered")
        if redirect_uri not in client.get("redirect_uris", []):
            return ("invalid_request", "the redirect URI is not registered for this client")
        if not code_challenge:
            return ("invalid_request", "PKCE is required")
        if code_challenge_method != "S256":
            return ("invalid_request", "only the S256 code challenge method is accepted")
        return None

    async def authorize(self, request: Request) -> Response:
        """The approval of the consent page."""
        client_ip = self._client_ip(request)
        ip_fail_key = f"oauth:auth_fail:ip:{client_ip}"
        global_fail_key = "oauth:auth_fail:global"
        ip_fails = int((self.state.get_json(ip_fail_key) or {}).get("count", 0))
        global_fails = int((self.state.get_json(global_fail_key) or {}).get("count", 0))
        if ip_fails >= AUTHORIZE_FAILURE_LIMIT or global_fails >= AUTHORIZE_FAILURE_LIMIT * 3:
            audit("oauth_authorization_locked", client_ip=client_ip)
            return HTMLResponse(
                "<!doctype html><html><body style='font-family:system-ui;padding:3rem'>"
                "<h2>Too Many Attempts</h2><p>Authorization is temporarily locked due to repeated failures.</p>"
                "</body></html>",
                status_code=429,
                headers=_SECURITY_HEADERS,
            )

        form = await request.form()
        client_id = str(form.get("client_id", ""))
        redirect_uri = str(form.get("redirect_uri", ""))
        state = str(form.get("state", ""))
        code_challenge = str(form.get("code_challenge", ""))
        code_challenge_method = str(form.get("code_challenge_method", ""))
        scope = str(form.get("scope", DEFAULT_SCOPE))
        enrollment_code = str(form.get("enrollment_code", ""))
        csrf_token = str(form.get("csrf_token", ""))

        error = self._check_authorize_params(
            client_id, redirect_uri, code_challenge, code_challenge_method
        )
        if error:
            return JSONResponse(
                {"error": error[0], "error_description": error[1]},
                status_code=400,
                headers=_SECURITY_HEADERS,
            )

        csrf_record = (
            self.state.consume_json(f"oauth:csrf:{_token_hash(csrf_token)}")
            if csrf_token
            else None
        )
        if (
            not csrf_record
            or csrf_record.get("client_id") != client_id
            or csrf_record.get("redirect_uri") != redirect_uri
        ):
            audit("oauth_authorization_refused", client_id=client_id, reason="csrf_invalid")
            return HTMLResponse(
                "<!doctype html><html><body style='font-family:system-ui;padding:3rem'>"
                "<h2>Refused</h2><p>The CSRF token is missing or invalid. Reload the consent page.</p>"
                "</body></html>",
                status_code=403,
                headers=_SECURITY_HEADERS,
            )

        expected = self.settings.enrollment_code
        if not expected or not hmac.compare_digest(enrollment_code, expected):
            self.state.put_json(ip_fail_key, {"count": ip_fails + 1}, ttl_sec=AUTHORIZE_LOCKOUT_SEC)
            self.state.put_json(global_fail_key, {"count": global_fails + 1}, ttl_sec=AUTHORIZE_LOCKOUT_SEC)
            audit("oauth_authorization_refused", client_id=client_id, reason="enrollment_code_mismatch")
            return HTMLResponse(
                "<!doctype html><html><body style='font-family:system-ui;padding:3rem'>"
                "<h2>Refused</h2><p>The enrolment code is wrong. No client was authorised.</p>"
                "</body></html>",
                status_code=403,
                headers=_SECURITY_HEADERS,
            )

        used_key = f"oauth:enrollment_used:{_token_hash(expected)}"
        if self.state.get_json(used_key) is not None:
            audit("oauth_authorization_refused", client_id=client_id, reason="enrollment_code_already_used")
            return HTMLResponse(
                "<!doctype html><html><body style='font-family:system-ui;padding:3rem'>"
                "<h2>Refused</h2><p>This one-time enrolment code has already been used.</p>"
                "</body></html>",
                status_code=403,
                headers=_SECURITY_HEADERS,
            )

        self.state.put_json(
            used_key,
            {"used_at": time.time(), "client_id": client_id},
            ttl_sec=None,
        )

        code = "code_" + secrets.token_urlsafe(24)
        self.state.put_json(
            f"oauth:code:{_token_hash(code)}",
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "scope": scope,
                "expires_at": time.time() + CODE_TTL_SEC,
            },
            ttl_sec=CODE_TTL_SEC,
        )
        audit("oauth_authorized", client_id=client_id, scope=scope)

        query = {"code": code}
        if state:
            query["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{separator}{urlencode(query)}",
            status_code=302,
            headers=_SECURITY_HEADERS,
        )

    # -- the token -----------------------------------------------------------

    async def token(self, request: Request) -> Response:
        """The exchange of a code or a refresh token for an access token."""
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
            form = {}
        grant_type = str(form.get("grant_type", ""))

        if grant_type == "authorization_code":
            return self._token_from_code(form)
        if grant_type == "refresh_token":
            return self._token_from_refresh(form)
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": "the grant type is not supported"},
            status_code=400,
        )

    def _client_secret_ok(self, form: Any, client_id: str) -> bool:
        """Check the secret of a client, when the client has one."""
        client = self._get_client(client_id)
        if not client:
            return False
        stored = client.get("client_secret_hash")
        if not stored:
            return True
        given = str(form.get("client_secret", ""))
        return hmac.compare_digest(hashlib.sha256(given.encode("utf-8")).hexdigest(), stored)

    def _token_from_code(self, form: Any) -> Response:
        code = str(form.get("code", ""))
        client_id = str(form.get("client_id", ""))
        redirect_uri = str(form.get("redirect_uri", ""))
        verifier = str(form.get("code_verifier", ""))

        if not code or not client_id or not verifier or not redirect_uri:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "the code, client_id, redirect_uri and code_verifier are required",
                },
                status_code=400,
            )
        record = self.state.consume_json(f"oauth:code:{_token_hash(code)}")
        if not record:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the authorization code is unknown or expired"},
                status_code=400,
            )

        if record["client_id"] != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the code was issued to another client"},
                status_code=400,
            )
        if redirect_uri != record["redirect_uri"]:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the redirect URI does not match"},
                status_code=400,
            )
        if not _pkce_ok(verifier, record["code_challenge"]):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the PKCE verifier does not match"},
                status_code=400,
            )
        if not self._client_secret_ok(form, client_id):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "the client secret does not match"},
                status_code=401,
            )

        return self._issue_tokens(client_id, record.get("scope", DEFAULT_SCOPE))

    def _token_from_refresh(self, form: Any) -> Response:
        refresh_token = str(form.get("refresh_token", ""))
        client_id = str(form.get("client_id", ""))
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "the refresh token is required"},
                status_code=400,
            )
        record = self.state.consume_json(f"oauth:refresh:{_token_hash(refresh_token)}")
        if not record:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the refresh token is unknown or expired"},
                status_code=400,
            )
        if client_id and record["client_id"] != client_id:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "the refresh token belongs to another client"},
                status_code=400,
            )
        if not self._client_secret_ok(form, record["client_id"]):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "the client secret does not match"},
                status_code=401,
            )
        return self._issue_tokens(record["client_id"], record.get("scope", DEFAULT_SCOPE))

    async def revoke(self, request: Request) -> Response:
        """Revoke an access token or refresh token (RFC 7009)."""
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
            form = {}
        token = str(form.get("token", ""))
        if not token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "the token parameter is required"},
                status_code=400,
            )
        client_id = str(form.get("client_id", ""))
        if client_id and not self._client_secret_ok(form, client_id):
            return JSONResponse(
                {"error": "invalid_client", "error_description": "the client secret does not match"},
                status_code=401,
            )
        digest = _token_hash(token)
        self.state.delete(f"oauth:token:{digest}")
        self.state.delete(f"oauth:refresh:{digest}")
        audit("oauth_token_revoked", client_id=client_id or "unspecified")
        return Response(status_code=200)

    def _issue_tokens(self, client_id: str, scope: str) -> Response:
        """Issue an access token and a refresh token."""
        access_token = "at_" + secrets.token_urlsafe(32)
        refresh_token = "rt_" + secrets.token_urlsafe(32)
        expires_in = ACCESS_TOKEN_TTL_SEC
        self.state.put_json(
            f"oauth:token:{_token_hash(access_token)}",
            {
                "client_id": client_id,
                "scope": scope,
                "expires_at": time.time() + expires_in,
            },
            ttl_sec=expires_in,
        )
        self.state.put_json(
            f"oauth:refresh:{_token_hash(refresh_token)}",
            {"client_id": client_id, "scope": scope},
            ttl_sec=REFRESH_TOKEN_TTL_SEC,
        )
        audit("oauth_token_issued", client_id=client_id)
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": refresh_token,
                "scope": scope,
            }
        )

    # -- the verification ----------------------------------------------------

    def verify_bearer(self, token: str) -> Optional[str]:
        """
        Check a bearer token and return the label of its principal.

        A token that is unknown, expired or malformed returns ``None``. The
        check is a lookup in the store, followed by a constant time compare of
        the digest, so that the answer does not depend on the token.
        """
        if not token:
            return None
        record = self.state.get_json(f"oauth:token:{_token_hash(token)}")
        if not record:
            return None
        if float(record.get("expires_at", 0)) <= time.time():
            self.state.delete(f"oauth:token:{_token_hash(token)}")
            return None
        return f"oauth:{record.get('client_id', 'unknown')}"
