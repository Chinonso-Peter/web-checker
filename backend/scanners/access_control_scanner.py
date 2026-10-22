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
]

# Bodies that merely "return 200" but are actually 404 pages or catch-all
# shells. Reporting these as exposed admin panels is the #1 FP here.
SOFT_404_MARKERS = [
    "not found",
    "page not found",
    "404",
    "no such page",
    "doesn't exist",
    "does not exist",
    "error 404",
    "this page could not be found",
]

# Text that indicates the 200 body is actually an admin / management page and
# not some generic shell page.
ADMIN_CONTENT_MARKERS = [
    "admin",
    "dashboard",
    "admin panel",
    "user management",
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
    return any(m in low for m in SOFT_404_MARKERS)


def _looks_like_admin(body):
    low = body.lower()
    return any(m in low for m in ADMIN_CONTENT_MARKERS)


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    findings = []
    handler = RequestHandler(cookies=cookies, headers=headers)
    base = normalize_url(target_url).rstrip("/")
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    # Baseline home page body used to reject shells that return identical HTML
    # for every path (common on SPA / catch-all routers).
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
        for path in ADMIN_PATHS:
            test_url = b + path
            if test_url in tested_urls:
                continue
            tested_urls.add(test_url)
            resp = handler.get(test_url)
            if resp is None:
                continue

            # 301/302 -> almost always a redirect to login or a rewritten location.
            # That is auth ENFORCEMENT, not a finding. 403/401 = enforced. Skip both.
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
                # Same shell as the homepage -> framework catch-all, not an admin page.
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

    return findings