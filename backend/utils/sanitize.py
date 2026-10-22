"""Input sanitization utilities for preventing XSS, SQL injection, and other attacks."""
import html
import re
from typing import Optional
from markupsafe import escape as safe_escape


# HTML sanitization - allow only safe tags/attributes for rich text if needed
ALLOWED_TAGS = set()
ALLOWED_ATTRIBUTES = {}

# Patterns for detecting malicious input
SQL_INJECTION_PATTERNS = [
    r"(?i)(\bunion\b.*\bselect\b)",
    r"(?i)(\bselect\b.*\bfrom\b)",
    r"(?i)(\binsert\b.*\binto\b)",
    r"(?i)(\bupdate\b.*\bset\b)",
    r"(?i)(\bdelete\b.*\bfrom\b)",
    r"(?i)(\bdrop\b.*\btable\b)",
    r"(?i)(\bor\b\s+\d+\s*=\s*\d+)",
    r"(?i)(\band\b\s+\d+\s*=\s*\d+)",
    r"(?i)(;\s*--)",
    r"(?i)(\bxp_cmdshell\b)",
    r"(?i)(\bexec\b\s*\()",
    r"(?i)(\bsp_\w+\b)",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe",
    r"<object",
    r"<embed",
    r"<link",
    r"<meta",
    r"expression\s*\(",
    r"vbscript:",
    r"data:text/html",
]


def sanitize_html(value: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    return safe_escape(value)


def sanitize_text(value: str, max_length: Optional[int] = None) -> str:
    """Basic text sanitization - strip, normalize whitespace, optional length limit."""
    if not value:
        return ""
    value = value.strip()
    # Normalize whitespace
    value = re.sub(r"\s+", " ", value)
    if max_length and len(value) > max_length:
        value = value[:max_length]
    return value


def sanitize_username(value: str) -> str:
    """Sanitize username - alphanumeric, underscore, hyphen only."""
    if not value:
        return ""
    value = value.strip().lower()
    # Only allow alphanumeric, underscore, hyphen
    value = re.sub(r"[^a-z0-9_-]", "", value)
    return value[:30]


def sanitize_email(value: str) -> str:
    """Sanitize and validate email."""
    if not value:
        return ""
    value = value.strip().lower()
    # Basic email format validation
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", value):
        return ""
    return value[:100]


def sanitize_url(value: str) -> str:
    """Sanitize URL - ensure it's a valid http/https URL."""
    if not value:
        return ""
    value = value.strip()
    # Only allow http/https URLs
    if not re.match(r"^https?://", value, re.IGNORECASE):
        return ""
    # Length limit
    if len(value) > 2048:
        return ""
    # Basic URL validation
    if not re.match(r"^https?://[^\s/$.?#].[^\s]*$", value, re.IGNORECASE):
        return ""
    return value


def sanitize_password(value: str) -> str:
    """Sanitize password - don't modify, just validate length."""
    if not value:
        return ""
    # Don't strip passwords - spaces might be intentional
    # Just validate length
    if len(value) < 6 or len(value) > 128:
        return ""
    return value


def detect_sql_injection(value: str) -> bool:
    """Check for potential SQL injection patterns."""
    if not value:
        return False
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value):
            return True
    return False


def detect_xss(value: str) -> bool:
    """Check for potential XSS patterns."""
    if not value:
        return False
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False


def sanitize_input(value: str, input_type: str = "text", max_length: Optional[int] = None) -> str:
    """
    Main sanitization function - routes to appropriate sanitizer.
    
    Args:
        value: Raw input string
        input_type: Type of input - 'text', 'username', 'email', 'url', 'password', 'html'
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    
    Raises:
        ValueError: If malicious patterns detected
    """
    if value is None:
        return ""
    
    # Check for malicious patterns on all non-password inputs
    if input_type != "password":
        if detect_sql_injection(value):
            raise ValueError("Potential SQL injection detected")
        if detect_xss(value):
            raise ValueError("Potential XSS detected")
    
    # Route to specific sanitizer
    if input_type == "username":
        return sanitize_username(value)
    elif input_type == "email":
        return sanitize_email(value)
    elif input_type == "url":
        return sanitize_url(value)
    elif input_type == "password":
        return sanitize_password(value)
    elif input_type == "html":
        return sanitize_html(value)
    else:
        return sanitize_text(value, max_length)


def sanitize_dict(data: dict, schema: dict) -> dict:
    """
    Sanitize a dictionary of inputs based on a schema.
    
    Schema format:
    {
        "field_name": {"type": "text", "max_length": 100, "required": True},
        "email": {"type": "email", "required": True},
        ...
    }
    """
    sanitized = {}
    errors = {}
    
    for field, rules in schema.items():
        input_type = rules.get("type", "text")
        max_length = rules.get("max_length")
        required = rules.get("required", False)
        default = rules.get("default", "")
        
        raw_value = data.get(field, default)
        
        if required and not raw_value:
            errors[field] = f"{field} is required"
            continue
        
        if not raw_value:
            sanitized[field] = default
            continue
        
        try:
            sanitized[field] = sanitize_input(raw_value, input_type, max_length)
        except ValueError as e:
            errors[field] = str(e)
    
    if errors:
        raise ValueError(errors)
    
    return sanitized