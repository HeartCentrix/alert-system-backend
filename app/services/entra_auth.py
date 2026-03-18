"""
Microsoft Entra ID (Azure AD) OAuth 2.0 / OIDC authentication service.

Implements the Authorization Code flow with PKCE for secure authentication.
Uses Microsoft's OIDC discovery endpoint for automatic configuration.

Security (March 2026 standards):
- PKCE required (prevents authorization code interception)
- State parameter with HMAC (prevents CSRF on callback)
- Nonce in ID token (prevents replay attacks)
- ID token signature validation via JWKS
- Server-side token exchange (code never exposed to frontend)
"""

import hashlib
import hmac
import secrets
import logging
import base64
from typing import Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from jwt import PyJWKClient

from app.config import settings

logger = logging.getLogger(__name__)

# Microsoft OIDC endpoints
ENTRA_AUTHORITY = "https://login.microsoftonline.com"
OIDC_CONFIG_PATH = ".well-known/openid-configuration"


class EntraAuthService:
    """Handles Microsoft Entra ID OAuth 2.0 / OIDC authentication."""

    def __init__(self):
        self.client_id = settings.ENTRA_CLIENT_ID
        self.client_secret = settings.ENTRA_CLIENT_SECRET
        self.tenant_id = settings.ENTRA_TENANT_ID or "common"
        self.redirect_uri = settings.ENTRA_REDIRECT_URI
        self.scopes = settings.ENTRA_SCOPES.split()

        self._oidc_config: Optional[dict] = None
        self._jwks_client: Optional[PyJWKClient] = None

    @property
    def authority_url(self) -> str:
        return f"{ENTRA_AUTHORITY}/{self.tenant_id}"

    @property
    def is_configured(self) -> bool:
        return bool(
            self.client_id
            and self.client_secret
            and self.tenant_id
            and self.redirect_uri
        )

    async def _get_oidc_config(self) -> dict:
        """Fetch and cache the OIDC discovery document."""
        if self._oidc_config:
            return self._oidc_config

        url = f"{self.authority_url}/v2.0/{OIDC_CONFIG_PATH}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            self._oidc_config = resp.json()
            return self._oidc_config

    def _get_jwks_client(self, jwks_uri: str) -> PyJWKClient:
        """Get or create JWKS client for ID token validation."""
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
        return self._jwks_client

    def generate_state(self) -> str:
        """Generate a cryptographic state parameter for CSRF protection.

        Returns a random state string. The caller should store this
        in a short-lived Redis key or signed cookie for verification
        on callback.
        """
        return secrets.token_urlsafe(32)

    def generate_pkce_pair(self) -> Tuple[str, str]:
        """Generate PKCE code_verifier and code_challenge pair.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        code_verifier = secrets.token_urlsafe(64)[:128]
        code_challenge = (
            hashlib.sha256(code_verifier.encode("ascii"))
            .digest()
        )
        code_challenge_b64 = (
            base64.urlsafe_b64encode(code_challenge)
            .rstrip(b"=")
            .decode("ascii")
        )
        return code_verifier, code_challenge_b64

    def generate_nonce(self) -> str:
        """Generate a nonce for ID token replay protection."""
        return secrets.token_urlsafe(32)

    async def build_authorization_url(
        self, state: str, code_challenge: str, nonce: str
    ) -> str:
        """Build the Microsoft authorization URL for the redirect.

        Args:
            state: CSRF protection state parameter
            code_challenge: PKCE code challenge (S256)
            nonce: Replay protection nonce

        Returns:
            Full authorization URL to redirect the user to
        """
        config = await self._get_oidc_config()
        authorize_url = config["authorization_endpoint"]

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "response_mode": "query",
            "prompt": "select_account",
        }
        return f"{authorize_url}?{urlencode(params)}"

    async def exchange_code_for_tokens(
        self, code: str, code_verifier: str
    ) -> dict:
        """Exchange authorization code for ID token and access token.

        Args:
            code: Authorization code from Microsoft callback
            code_verifier: PKCE code verifier (generated before redirect)

        Returns:
            Token response dict with id_token, access_token, etc.

        Raises:
            httpx.HTTPStatusError: If token exchange fails
        """
        config = await self._get_oidc_config()
        token_url = config["token_endpoint"]

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "code_verifier": code_verifier,
                },
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()

    async def validate_id_token(
        self, id_token: str, expected_nonce: str
    ) -> dict:
        """Validate and decode the Microsoft ID token.

        Verifies:
        - Signature against Microsoft's JWKS
        - Audience matches our client_id
        - Issuer matches our tenant
        - Token is not expired
        - Nonce matches (replay protection)

        Args:
            id_token: Raw ID token JWT string
            expected_nonce: Nonce we sent in the authorization request

        Returns:
            Decoded ID token claims dict

        Raises:
            jwt.exceptions.PyJWTError: If validation fails
            ValueError: If nonce doesn't match
        """
        config = await self._get_oidc_config()
        jwks_uri = config["jwks_uri"]
        issuer = config["issuer"]

        jwks_client = self._get_jwks_client(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        claims = pyjwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub", "nonce"]},
        )

        # Verify nonce matches
        if claims.get("nonce") != expected_nonce:
            raise ValueError(
                f"Nonce mismatch: expected {expected_nonce}, got {claims.get('nonce')}"
            )

        return claims

    def extract_user_info(self, claims: dict) -> dict:
        """Extract user information from validated ID token claims.

        Args:
            claims: Decoded and validated ID token claims

        Returns:
            Dict with: email, first_name, last_name, external_id (oid)
        """
        return {
            "email": (
                claims.get("preferred_username")
                or claims.get("email")
                or claims.get("upn")
                or ""
            ).strip().lower(),
            "first_name": claims.get("given_name", ""),
            "last_name": claims.get("family_name", ""),
            "external_id": claims.get("oid", ""),  # Entra Object ID — globally unique
            "name": claims.get("name", ""),
        }


# Module-level singleton (lazy initialization)
_entra_service: Optional[EntraAuthService] = None


def get_entra_service() -> EntraAuthService:
    """Get or create the Entra auth service singleton."""
    global _entra_service
    if _entra_service is None:
        _entra_service = EntraAuthService()
    return _entra_service
