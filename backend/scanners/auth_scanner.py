from urllib.parse import urlparse

from backend.core.request_handler import RequestHandler
from backend.core.url_utils import is_valid_url, normalize_url


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    """Report only provable auth weaknesses, not the existence of a login form."""
    findings = []
    handler = RequestHandler(cookies=cookies, headers=headers)
    seen = set()

    for form in forms:
        inputs = form.get("inputs", [])
        has_password = any(inp.get("type") == "password" for inp in inputs)
        if not has_password:
            continue

        raw_action = form.get("action")
        action = normalize_url(raw_action or target_url)
        if not is_valid_url(action):
            continue

        # Deduplicate if multiple login forms point at the same action.
        key = (action, form.get("method", "post").lower())
        if key in seen:
            continue
        seen.add(key)

        # Credentials being POSTed over plain HTTP is a real, provable weakness.
        if urlparse(action).scheme != "https":
            findings.append(
                {
                    "severity": "medium",
                    "url": action,
                    "detail": (
                        "Login form submits credentials over unencrypted HTTP. "
                        "Passwords can be read or modified in transit."
                    ),
                    "payload": None,
                }
            )

        # Sensitive credentials transmitted via HTTP GET (CWE-598)
        if form.get("method", "post").lower() == "get":
            findings.append(
                {
                    "severity": "high",
                    "url": action,
                    "detail": (
                        "Login form transmits password credentials via HTTP GET. "
                        "Sensitive credentials will be exposed in browser history, web server logs, and Referer headers."
                    ),
                    "payload": None,
                }
            )

    return findings