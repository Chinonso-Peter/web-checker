import re
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

COMMON_API_SPECS = [
    "/static/openapi.json",
    "/openapi.json",
    "/swagger.json",
    "/api/swagger.json",
    "/api/docs/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
]

KNOWN_VARIABLE_DEFAULTS = {
    "version": "1",
    "account_number": "0242724394",
    "user_id": "1",
    "loan_id": "1",
    "card_id": "1",
    "category_id": "1",
    "payment_id": "1",
    "merchant_id": "1",
    "id": "1",
}


def _resolve_template_path(path):
    """Substitutes OpenAPI path templates like /api/v{version}/... with realistic test defaults."""
    res = path
    for var, default_val in KNOWN_VARIABLE_DEFAULTS.items():
        res = res.replace(f"{{{var}}}", default_val)
    # Generic fallback for any remaining {param}
    res = re.sub(r"\{[a-zA-Z0-9_-]+\}", "1", res)
    return res


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

    def _discover_openapi_endpoints(self, base_origin):
        """Discovers API endpoints defined in OpenAPI/Swagger specifications."""
        api_endpoints = []
        for spec_path in COMMON_API_SPECS:
            spec_url = join_url(base_origin, spec_path)
            try:
                resp = self.handler.get(spec_url)
                if not resp or resp.status_code != 200 or not resp.text:
                    continue
                data = resp.json()
                if not isinstance(data, dict) or ("paths" not in data and "swagger" not in data and "openapi" not in data):
                    continue
                paths = data.get("paths", {})
                for raw_path, methods in paths.items():
                    if not isinstance(methods, dict):
                        continue
                    for method_name, details in methods.items():
                        method_lower = method_name.lower()
                        if method_lower not in ("get", "post", "put", "delete", "patch"):
                            continue
                        inputs = []
                        # 1. Query/Path parameters
                        for param in details.get("parameters", []):
                            if isinstance(param, dict) and param.get("name"):
                                pname = param["name"]
                                inputs.append({
                                    "name": pname,
                                    "type": "text",
                                    "value": param.get("example", KNOWN_VARIABLE_DEFAULTS.get(pname, "1")),
                                    "in": param.get("in", "query"),
                                })
                        # 2. JSON RequestBody schema properties
                        req_body = details.get("requestBody", {})
                        is_json = False
                        if isinstance(req_body, dict):
                            content = req_body.get("content", {})
                            if "application/json" in content:
                                is_json = True
                                json_schema = content.get("application/json", {}).get("schema", {})
                                props = json_schema.get("properties", {})
                                for prop_name, prop_meta in props.items():
                                    inputs.append({
                                        "name": prop_name,
                                        "type": "password" if "password" in prop_name.lower() else "text",
                                        "value": prop_meta.get("example", prop_name),
                                        "in": "body",
                                    })

                        # Resolve {path} variables so scanners can probe the real URL
                        resolved_path = _resolve_template_path(raw_path)
                        full_action = join_url(base_origin, resolved_path)
                        raw_action = join_url(base_origin, raw_path)
                        api_endpoints.append({
                            "action": full_action,
                            "raw_action": raw_action,
                            "method": method_lower,
                            "inputs": inputs,
                            "content_type": "json" if is_json else "form",
                        })
                break
            except Exception:
                continue
        return api_endpoints

    def _extract_script_api_calls(self, html_text, page_url):
        """Extracts REST/JSON fetch and axios API endpoints declared in JavaScript code."""
        endpoints = []
        fetch_matches = re.finditer(
            r"""fetch\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*\{([^}]+)\})?""",
            html_text,
            re.DOTALL,
        )
        for m in fetch_matches:
            raw_url = m.group(1).strip()
            if not raw_url or raw_url.startswith(("#", "javascript:", "mailto:")):
                continue
            opts = m.group(2) or ""
            method_match = re.search(r"""method\s*:\s*['"]([a-zA-Z]+)['"]""", opts, re.IGNORECASE)
            method = method_match.group(1).lower() if method_match else "get"
            is_json = "application/json" in opts.lower() or "json.stringify" in opts.lower()

            full_action = join_url(page_url, raw_url)
            if is_valid_url(full_action):
                endpoints.append({
                    "action": full_action,
                    "method": method,
                    "inputs": [],
                    "content_type": "json" if is_json else "form",
                })
        return endpoints

    def crawl(self):
        if not self.target_url or not is_valid_url(self.target_url):
            return []

        parsed_target = urlparse(self.target_url)
        origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        # If the target URL contains query parameters, treat them as a form endpoint
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
                    "content_type": "form",
                })

        # Discover API specifications if present (e.g. VulnBank OpenAPI / Swagger)
        spec_endpoints = self._discover_openapi_endpoints(origin)
        if spec_endpoints:
            self.forms.extend(spec_endpoints)

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

            # Extract client-side fetch/API calls from page scripts
            script_endpoints = self._extract_script_api_calls(resp.text, page_url)
            script_endpoints_map = {e["action"]: e for e in script_endpoints}

            # 1. HTML <form> extraction
            for form in soup.find_all("form"):
                raw_action = form.get("action")
                action = join_url(page_url, raw_action) if raw_action else page_url
                raw_method = form.get("method")
                method = raw_method.lower() if raw_method else "post"
                content_type = "form"

                for ep_action, ep_meta in script_endpoints_map.items():
                    if ep_meta.get("content_type") == "json":
                        content_type = "json"
                        method = ep_meta.get("method", method)
                        action = ep_action
                        break

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
                    {"action": action, "method": method, "inputs": inputs, "content_type": content_type}
                )

            # 2. Standalone inputs outside of <form> tags (e.g., search boxes like on /blog)
            orphan_inputs = []
            for inp in soup.find_all(["input", "textarea"]):
                if inp.find_parent("form") is None:
                    name = inp.get("name") or inp.get("id")
                    if name:
                        orphan_inputs.append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        })
            if orphan_inputs:
                self.forms.append({
                    "action": page_url,
                    "method": "get",
                    "inputs": orphan_inputs,
                    "content_type": "form",
                })

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

        # Deduplicate forms
        unique_forms = []
        seen_keys = set()
        for f in self.forms:
            input_names = tuple(sorted(i["name"] for i in f.get("inputs", [])))
            key = (f.get("action"), f.get("method"), input_names, f.get("content_type"))
            if key not in seen_keys:
                seen_keys.add(key)
                unique_forms.append(f)

        return unique_forms
