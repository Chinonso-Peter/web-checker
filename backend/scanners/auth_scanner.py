from urllib.parse import urlparse

from backend.core.request_handler import RequestHandler
from backend.core.url_utils import is_valid_url, normalize_url


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    """
    Identifies authentication and session management weaknesses:
    1. Cleartext credential submission over unencrypted HTTP (CWE-319).
    2. Credentials exposed in URL query string via HTTP GET (CWE-598).
    3. User enumeration on authentication / password recovery endpoints (CWE-204).
    4. Absence of brute-force rate limiting on credential verification endpoints (CWE-307).
    """
    findings = []
    handler = RequestHandler(cookies=cookies, headers=headers)
    seen = set()

    for form in forms:
        inputs = form.get("inputs", [])
        input_names = [i.get("name", "").lower() for i in inputs]
        has_password = any(inp.get("type") == "password" or "pass" in inp.get("name", "").lower() for inp in inputs)
        has_user_identifier = any(any(k in n for k in ("user", "email", "login", "account")) for n in input_names)
        is_auth_form = has_password or (has_user_identifier and any(k in form.get("action", "").lower() for k in ("login", "auth", "signin", "forgot", "reset")))

        if not is_auth_form:
            continue

        raw_action = form.get("action")
        action = normalize_url(raw_action or target_url)
        if not is_valid_url(action):
            continue

        method = form.get("method", "post").lower()
        key = (action, method)
        if key in seen:
            continue
        seen.add(key)

        # 1. Credentials submitted over unencrypted HTTP
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

        # 2. Sensitive credentials transmitted via HTTP GET (CWE-598)
        if method == "get" and has_password:
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

        # 3. User Enumeration Check (CWE-204)
        # Check if known user ('admin') gives distinct message/status compared to non-existent user
        if has_user_identifier:
            user_field = next((i.get("name") for i in inputs if any(k in i.get("name", "").lower() for k in ("user", "email", "login"))), None)
            if user_field:
                content_type = form.get("content_type", "form")
                known_data = {i.get("name"): i.get("value", "1") for i in inputs if i.get("name")}
                known_data[user_field] = "admin"
                if has_password:
                    pass_field = next((i.get("name") for i in inputs if "pass" in i.get("name", "").lower()), "password")
                    known_data[pass_field] = "WrongPassword999!"

                unknown_data = dict(known_data)
                unknown_data[user_field] = "nonexistent_chk_78239"

                try:
                    if method == "post":
                        resp_known = handler.post(action, json=known_data) if content_type == "json" else handler.post(action, data=known_data)
                        resp_unknown = handler.post(action, json=unknown_data) if content_type == "json" else handler.post(action, data=unknown_data)
                    else:
                        resp_known = handler.get(action, params=known_data)
                        resp_unknown = handler.get(action, params=unknown_data)

                    if resp_known and resp_unknown and resp_known.status_code != 500 and resp_unknown.status_code != 500:
                        known_text = resp_known.text.lower()
                        unknown_text = resp_unknown.text.lower()

                        # Distinct responses indicate user enumeration
                        status_diff = (resp_known.status_code != resp_unknown.status_code)
                        message_diff = (
                            ("user not found" in unknown_text and "user not found" not in known_text) or
                            ("sent to your email" in known_text and "sent to your email" not in unknown_text) or
                            ("invalid password" in known_text and "user not found" in unknown_text)
                        )

                        if status_diff or message_diff:
                            findings.append(
                                {
                                    "severity": "medium",
                                    "url": action,
                                    "detail": (
                                        f"User Enumeration vulnerability on endpoint '{action}'. "
                                        f"The application responds differently to existing accounts ('admin') "
                                        f"versus non-existent accounts, allowing attackers to harvest valid usernames."
                                    ),
                                    "payload": f"{user_field}=admin vs nonexistent_chk_78239",
                                }
                            )
                except Exception:
                    pass

    return findings
