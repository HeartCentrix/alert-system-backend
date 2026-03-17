"""
Search input sanitization utilities.

Escapes special SQL LIKE/ILIKE wildcard characters in user-provided
search strings to prevent pattern-based denial-of-service attacks.

PostgreSQL LIKE wildcards:
  %  — matches any sequence of characters (zero or more)
  _  — matches exactly one character

Without escaping, a search for "%%%%" becomes the pattern "%%%%%%%%"
which forces a full table scan with expensive pattern matching.

Note: This is NOT about SQL injection — SQLAlchemy parameterizes values.
This is about preventing LIKE wildcard abuse for DoS.
"""


def escape_like(value: str) -> str:
    """
    Escape LIKE/ILIKE wildcard characters in a search string.
    
    Uses backslash as the escape character (PostgreSQL default).
    
    Args:
        value: Raw user input string
        
    Returns:
        Escaped string safe for use in LIKE/ILIKE patterns
        
    Examples:
        escape_like("John")       -> "John"        (no change)
        escape_like("100%")       -> "100\\%"      (% escaped)
        escape_like("test_user")  -> "test\\_user"  (_ escaped)
        escape_like("%%exploit")  -> "\\%\\%exploit" (both escaped)
    """
    # Escape backslash first (since we use it as the escape char),
    # then escape the wildcards
    return (
        value
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
