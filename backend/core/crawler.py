import time
from urllib.parse import urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from backend.core.auth_helper import resolve_target_cookies
from backend.core.request_handler import RequestHandler
from backend.core.url_utils import is_valid_url, join_url, normalize_url

DISALLOWED_LINK_PATTERNS = [
    "logout",
    "log-out",
    "logoff",
    "signout",
    "sign-out",
    "deauth",
    "disconnect",
    "setup.php",
]


class Crawler:
    def __init__(self, max_depth=1, delay=0.2, cookies=None, headers=None):
        self.max_depth = max_depth
        self.delay = delay
        # If PHPSESSID is passed without security level for DVWA, ensure security=low is set
        if cookies and isinstance(cookies, str) and "phpsessid" in cookies.lower() and "security=" not in cookies.lower():
            cookies = cookies.rstrip("; ") + "; security=low"
        self.cookies = cookies
        self.headers = headers
        self.handler = RequestHandler(cookies=cookies, headers=headers)
        self.visited = set()
        self.forms = []
        self.target_url = None

    def set_target(self, url):
        self.target_url = normalize_url(url)
        self.cookies = resolve_target_cookies(self.target_url, self.cookies)
        self.handler = RequestHandler(cookies=self.cookies, headers=self.headers)
        self.visited = set()
        self.forms = []

    def crawl(self):
        if not self.target_url or not is_valid_url(self.target_url):
            return []

        # If the target URL contains query parameters, treat them as a form endpoint
        parsed_target = urlparse(self.target_url)
        if parsed_target.query:
            qs = parse_qs(parsed_target.query)
            clean_action = urlunparse((parsed_target.scheme, parsed_target.netloc, parsed_target.path, "", "", ""))
            query_inputs = [
                {"name": k, "type": "text", "value": v[0] if v else ""}
                for k, v in qs.items()
            ]
            if query_inputs:
                self.forms.append({
                    "action": clean_action,
                    "method": "get",
                    "inputs": query_inputs,
                })

        base_host = parsed_target.netloc
        queue = [(self.target_url, 0)]

        while queue:
            current_url, depth = queue.pop(0)
            if depth > self.max_depth or current_url in self.visited:
                continue
            self.visited.add(current_url)

            resp = self.handler.get(current_url)
            if not resp or resp.status_code != 200:
                continue

            page_url = getattr(resp, "url", None) or current_url
            page_host = urlparse(page_url).netloc
            allowed_hosts = {base_host}
            if page_host:
                allowed_hosts.add(page_host)

            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception:
                continue

            for form in soup.find_all("form"):
                raw_action = form.get("action") or page_url
                action = join_url(page_url, raw_action)
                method = (form.get("method") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    tag_name = inp.name
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "textarea" if tag_name == "textarea" else "text"),
                        "value": inp.get("value", inp.text.strip() if tag_name == "textarea" else name),
                    })

                self.forms.append(
                    {"action": action, "method": method, "inputs": inputs}
                )

            if depth < self.max_depth:
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if not href or href.startswith(("#", "javascript:", "mailto:")):
                        continue

                    # Critical: Never crawl logout or reset endpoints that kill the active session
                    if any(pattern in href.lower() for pattern in DISALLOWED_LINK_PATTERNS):
                        continue

                    full = join_url(page_url, href)
                    if not is_valid_url(full):
                        continue
                    if urlparse(full).scheme not in ("http", "https"):
                        continue
                    if urlparse(full).netloc not in allowed_hosts:
                        continue

                    norm = normalize_url(full)
                    if any(pattern in norm.lower() for pattern in DISALLOWED_LINK_PATTERNS):
                        continue

                    if norm not in self.visited and norm not in [q[0] for q in queue]:
                        queue.append((norm, depth + 1))
                        time.sleep(self.delay)

        return self.forms
