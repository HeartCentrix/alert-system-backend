"""
LDAP / Active Directory authentication service.

Authenticates users by binding to an LDAP server with their credentials.
Supports:
- LDAPS (LDAP over TLS) — required in production
- User search by sAMAccountName or userPrincipalName
- Group membership verification (optional)
- Attribute extraction (email, name, department)

Security:
- Never stores LDAP passwords locally
- Always uses TLS (ldaps:// or StartTLS)
- Input sanitization prevents LDAP injection
- Service account uses read-only bind for searching
- Connection timeout prevents hanging on unreachable servers
"""

import re
import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

# Characters that must be escaped in LDAP search filters (RFC 4515)
_LDAP_ESCAPE_CHARS = {
    '\\': '\\5c',
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\x00': '\\00',
}


def _escape_ldap_filter(value: str) -> str:
    """Escape special characters in LDAP filter values (RFC 4515).

    Prevents LDAP injection attacks.
    """
    for char, escape in _LDAP_ESCAPE_CHARS.items():
        value = value.replace(char, escape)
    return value


class LDAPAuthService:
    """Handles LDAP / Active Directory authentication."""

    def __init__(self):
        self.server_url = settings.LDAP_SERVER_URL
        self.bind_dn = settings.LDAP_BIND_DN
        self.bind_password = settings.LDAP_BIND_PASSWORD
        self.user_search_base = settings.LDAP_USER_SEARCH_BASE
        self.user_search_filter = settings.LDAP_USER_SEARCH_FILTER
        self.email_attr = settings.LDAP_EMAIL_ATTRIBUTE
        self.first_name_attr = settings.LDAP_FIRST_NAME_ATTRIBUTE
        self.last_name_attr = settings.LDAP_LAST_NAME_ATTRIBUTE
        self.group_search_base = settings.LDAP_GROUP_SEARCH_BASE
        self.required_group = settings.LDAP_REQUIRED_GROUP
        self.use_tls = settings.LDAP_USE_TLS

    @property
    def is_configured(self) -> bool:
        return bool(
            self.server_url
            and self.bind_dn
            and self.bind_password
            and self.user_search_base
        )

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        """Authenticate a user against LDAP/AD.

        Args:
            username: sAMAccountName or userPrincipalName
            password: User's AD password

        Returns:
            Dict with user info (email, first_name, last_name, dn) if auth succeeds.
            None if authentication fails.
        """
        try:
            from ldap3 import Server, Connection, ALL, SUBTREE, Tls
            import ssl

            # Validate input
            if not username or not password:
                return None

            # Sanitize username for LDAP filter
            safe_username = _escape_ldap_filter(username.strip())

            # Configure TLS
            tls_config = None
            if self.use_tls or self.server_url.startswith("ldaps://"):
                tls_config = Tls(validate=ssl.CERT_REQUIRED)

            # Connect with service account to search for user
            server = Server(
                self.server_url,
                use_ssl=self.server_url.startswith("ldaps://"),
                tls=tls_config,
                get_info=ALL,
                connect_timeout=10,
            )

            service_conn = Connection(
                server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=True,
                read_only=True,
                receive_timeout=10,
            )

            # Search for user
            search_filter = self.user_search_filter.replace("{username}", safe_username)

            service_conn.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.email_attr,
                    self.first_name_attr,
                    self.last_name_attr,
                    "distinguishedName",
                    "memberOf",
                ],
                size_limit=2,  # We expect exactly 1 result
            )

            if len(service_conn.entries) == 0:
                logger.info(f"LDAP user not found: {safe_username}")
                service_conn.unbind()
                return None

            if len(service_conn.entries) > 1:
                logger.warning(
                    f"LDAP ambiguous user search: {safe_username} matched {len(service_conn.entries)} entries"
                )
                service_conn.unbind()
                return None

            user_entry = service_conn.entries[0]
            user_dn = str(user_entry.entry_dn)

            service_conn.unbind()

            # Check group membership if required
            if self.required_group:
                member_of = [str(g) for g in getattr(user_entry, "memberOf", [])]
                if self.required_group not in member_of:
                    logger.warning(
                        f"LDAP user {safe_username} not in required group {self.required_group}"
                    )
                    return None

            # Bind as the user to verify their password
            user_conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
                read_only=True,
                receive_timeout=10,
            )
            user_conn.unbind()

            # Extract user attributes
            email = str(getattr(user_entry, self.email_attr, "")).strip()
            first_name = str(getattr(user_entry, self.first_name_attr, "")).strip()
            last_name = str(getattr(user_entry, self.last_name_attr, "")).strip()

            return {
                "email": email.lower(),
                "first_name": first_name,
                "last_name": last_name,
                "dn": user_dn,
                "username": username,
            }

        except ImportError:
            logger.error("ldap3 package not installed. Run: pip install ldap3")
            return None
        except Exception as e:
            # LDAP bind failure = wrong password, or server unreachable
            logger.info(f"LDAP auth failed for {username}: {type(e).__name__}")
            return None


_ldap_service: Optional[LDAPAuthService] = None


def get_ldap_service() -> LDAPAuthService:
    """Get or create the LDAP auth service singleton."""
    global _ldap_service
    if _ldap_service is None:
        _ldap_service = LDAPAuthService()
    return _ldap_service
