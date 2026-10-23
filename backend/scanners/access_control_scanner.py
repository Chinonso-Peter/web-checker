import re
from urllib.parse import urlparse

from backend.core.request_handler import RequestHandler
from backend.core.url_utils import normalize_url

ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/manage",
    "/panel",
    "/dashboard",
    "/users",
    "/accounts",
    "/sup3r_s3cr3t_admin",
]

SENSITIVE_FILES = [
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.git/config",
    "/.git/HEAD",
    "/debug/users",
    "/config.json",
    "/internal/secret",
    "/internal/config.json",
]

# Regex patterns for bodies that merely "return 200" but are actually 404 pages or catch-all shells.
SOFT_404_PATTERNS = [
    r"\bnot found\b",
    r"\bpage not found\b",
    r"\b404 not found\b",
    r"\bhttp 404\b",
    r"\bno such page\b",
    r"\bdoesn't exist\b",
    r"\bdoes not exist\b",
    r"\berror 404\b",
    r"\bthis page could not be found\b",
]

# Text that indicates the 200 body is actually an admin / management page.
ADMIN_CONTENT_MARKERS = [
    "admin",
    "dashboard",
    "admin panel",
    "user management",
    "manage users",
    "administrator",
    "settings",
    "configuration",
    "backoffice",
    "control panel",
    "sensitive configuration",
]


def _looks_like_404(body):
    low = body.lower()
    return any(re.search(pat, low) for pat in SOFT_404_PATTERNS)


def _looks_like_admin(body):
    low = body.lower()
    return any(m in low for m in ADMIN_CONTENT_MARKERS)


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    findings = []
    handler = RequestHandler(cookies=cookies, headers=headers)
    base = normalize_url(target_url).rstrip("/")
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    try:
        root_resp = handler.get(base + "/")
        root_body = (root_resp.text if root_resp and root_resp.status_code == 200 else None)
    except Exception:
        root_body = None

    tested_urls = set()
    test_bases = [base]
    if origin and origin != base:
        test_bases.append(origin)

    for b in test_bases:
        # 1. Probe for Sensitive Unprotected Files and Debug Endpoints
        for s_file in SENSITIVE_FILES:
            file_url = b + s_file
            if file_url in tested_urls:
                continue
            tested_urls.add(file_url)

            resp = handler.get(file_url)
            if resp is None or resp.status_code != 200 or not resp.text:
                continue

            body = resp.text
            if _looks_like_404(body):
                continue
            if root_body is not None and body == root_body:
                continue

            body_lower = body.lower()
            is_env = any(k in body_lower for k in ("secret_key", "jwt_secret", "database_url", "app_env", "db_password"))
            is_debug_users = any(k in body_lower for k in ("users", "account_number", "password", "is_admin")) and "{" in body
            is_git = "[core]" in body or "ref: refs/" in body

            if is_env or is_debug_users or is_git:
                findings.append(
                    {
                        "severity": "critical",
                        "url": file_url,
                        "detail": (
                            f"Sensitive configuration / debug resource '{s_file}' is publicly accessible without authentication. "
                            f"Exposes environment secrets, credentials, or sensitive application metadata."
                        ),
                        "payload": s_file,
                    }
                )

        # 2. Probe for Administrative and Privileged Panels
        for path in ADMIN_PATHS:
            test_url = b + path
            if test_url in tested_urls:
                continue
            tested_urls.add(test_url)
            resp = handler.get(test_url)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 403, 401, 404, 500, 502, 503):
                continue

            if resp.status_code != 200 or not resp.text:
                continue

            body = resp.text
            if _looks_like_404(body):
                continue
            if not _looks_like_admin(body):
                continue
            if root_body is not None and body == root_body:
                continue

            findings.append(
                {
                    "severity": "medium",
                    "url": test_url,
                    "detail": (
                        f"Administrative endpoint '{path}' returns HTTP 200 with "
                        "admin-panel content. Verify it is not accessible to "
                        "unauthenticated users."
                    ),
                    "payload": path,
                }
            )

    # 3. Test Discovered API Endpoints for Broken Object-Level Authorization (BOLA / IDOR)
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        if not action or method != "get":
            continue

        # Check endpoints that take an identifier parameter (e.g. account_number, user_id, order_id)
        is_obj_endpoint = any(k in action.lower() for k in ("balance", "transaction", "account", "user", "order", "invoice", "statement"))
        if is_obj_endpoint and action not in tested_urls:
            tested_urls.add(action)
            resp = handler.get(action)
            if resp is not None and resp.status_code == 200 and resp.text:
                text_lower = resp.text.lower()
                has_financial_or_pii = any(k in text_lower for k in ("balance", "account_number", "transactions", "username", "email", "address"))
                if has_financial_or_pii and not _looks_like_404(resp.text):
                    findings.append(
                        {
                            "severity": "high",
                            "url": action,
                            "detail": (
                                f"Broken Object-Level Authorization (BOLA / IDOR) on '{action}'. "
                                f"The endpoint exposes sensitive user/financial object records without authentication."
                            ),
                            "payload": action,
                        }
                    )

    return findings
