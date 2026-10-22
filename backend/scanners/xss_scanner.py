import re
import time
from bs4 import BeautifulSoup

from backend.core.auth_helper import resolve_target_cookies
from backend.core.param_filters import is_user_parameter, unique_probe
from backend.core.request_handler import RequestHandler
from backend.core.url_utils import is_valid_url, normalize_url

MAX_TESTS = 60

DOM_SOURCES = [
    (r"document\.location(?:\.href|\.search|\.hash)?", "document.location"),
    (r"location\.(?:href|search|hash)", "location.href"),
    (r"window\.location(?:\.href|\.search|\.hash)?", "window.location"),
    (r"document\.URL", "document.URL"),
    (r"document\.referrer", "document.referrer"),
]

DOM_SINKS = [
    (r"document\.write(?:ln)?\(", "document.write"),
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"eval\(", "eval"),
    (r"setTimeout\(", "setTimeout"),
    (r"setInterval\(", "setInterval"),
]


def _probe_payload(probe):
    """Build payloads whose opening tag and unique function call double as detection markers."""
    return [
        f"<script>{probe}()</script>",
        f'"><script>{probe}()</script>',
        f"<img src=x onerror={probe}()>",
    ]


def _extract_form_defaults(form):
    defaults = {}
    for inp in form.get("inputs", []):
        name = inp.get("name")
        if name:
            defaults[name] = inp.get("value", name)
    return defaults


def _injection_points(forms, target_url, parameters):
    if parameters:
        urls = {target_url}
        for form in forms:
            action = normalize_url(form.get("action", target_url))
            if is_valid_url(action):
                urls.add(action)

        action_defaults = {}
        for form in forms:
            act = normalize_url(form.get("action", target_url))
            action_defaults[act] = _extract_form_defaults(form)

        seen_get = set()
        for url in urls:
            defaults = action_defaults.get(url, {})
            for pname in parameters:
                if not is_user_parameter(pname):
                    continue
                key = (url, pname)
                if key not in seen_get:
                    seen_get.add(key)
                    extra = {k: v for k, v in defaults.items() if k != pname}
                    yield url, "get", pname, extra

        seen_post = set()
        for form in forms:
            action = normalize_url(form.get("action", target_url))
            method = form.get("method", "get").lower()
            if method != "post" or not is_valid_url(action):
                continue
            defaults = _extract_form_defaults(form)
            for pname in parameters:
                if not is_user_parameter(pname):
                    continue
                key = (action, pname)
                if key not in seen_post:
                    seen_post.add(key)
                    extra = {k: v for k, v in defaults.items() if k != pname}
                    yield action, "post", pname, extra
        return

    seen_endpoints = set()
    for form in forms:
        action = normalize_url(form.get("action", target_url))
        method = form.get("method", "get").lower()
        if not is_valid_url(action):
            continue
        defaults = _extract_form_defaults(form)
        for inp in form.get("inputs", []):
            pname = inp.get("name")
            if not is_user_parameter(pname):
                continue
            key = (action, method, pname)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)
            extra = {k: v for k, v in defaults.items() if k != pname}
            yield action, method, pname, extra


def _check_dom_xss(handler, target_url):
    """
    Analyzes client-side JavaScript on the target page for DOM-based XSS flaws
    where untrusted sources (e.g. location.href) flow into dangerous sinks (e.g. document.write).
    """
    dom_findings = []
    try:
        resp = handler.get(target_url)
        if not resp or not resp.text:
            return dom_findings

        soup = BeautifulSoup(resp.text, "html.parser")
        for script in soup.find_all("script"):
            content = script.string or script.text or ""
            if not content.strip():
                continue

            matched_source = None
            for pattern, name in DOM_SOURCES:
                if re.search(pattern, content):
                    matched_source = name
                    break

            matched_sink = None
            for pattern, name in DOM_SINKS:
                if re.search(pattern, content):
                    matched_sink = name
                    break

            if matched_source and matched_sink:
                param_match = re.search(r"['\"]([a-zA-Z0-9_-]+)=['\"]", content)
                pname = param_match.group(1) if param_match else "URL parameter"
                dom_findings.append(
                    {
                        "severity": "high",
                        "url": target_url,
                        "detail": (
                            f"DOM-Based Cross-Site Scripting (DOM XSS) detected on parameter '{pname}'. "
                            f"Client-side script reads from source '{matched_source}' and passes "
                            f"untrusted data directly into execution sink '{matched_sink}'."
                        ),
                        "payload": f"?{pname}=<script>alert('DOM-XSS')</script>",
                    }
                )
    except Exception:
        pass
    return dom_findings


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    findings = []
    cookies = resolve_target_cookies(target_url, cookies=cookies)
    handler = RequestHandler(cookies=cookies, headers=headers)
    tests = 0

    # 1. Check for DOM-Based XSS in client-side scripts
    dom_findings = _check_dom_xss(handler, target_url)
    findings.extend(dom_findings)

    # 2. Check for Reflected and Stored XSS across discovered forms and parameters
    for action, method, inp_name, extra in _injection_points(forms, target_url, parameters):
        if tests >= MAX_TESTS:
            break

        probe = unique_probe("wc_xss")
        for payload in _probe_payload(probe):
            send_data = {**extra, inp_name: payload}
            try:
                if method == "post":
                    resp = handler.post(action, data=send_data)
                else:
                    resp = handler.get(action, params=send_data)
            except Exception:
                resp = None
            tests += 1

            if resp is None or not resp.text:
                continue

            # Verify if payload is reflected directly or persisted (Stored XSS)
            is_vulnerable = False
            is_stored = False

            if payload in resp.text or f"{probe}()" in resp.text:
                is_vulnerable = True
                if method == "post":
                    is_stored = True
            elif method == "post":
                # For POST endpoints (like guestbooks), follow up with a GET to check persistence
                try:
                    follow_resp = handler.get(action)
                    if follow_resp and (payload in follow_resp.text or f"{probe}()" in follow_resp.text):
                        is_vulnerable = True
                        is_stored = True
                except Exception:
                    pass

            if is_vulnerable:
                vuln_type = "Stored / Persistent Cross-Site Scripting (XSS)" if is_stored else "Reflected Cross-Site Scripting (XSS)"
                vuln_desc = (
                    f"{vuln_type} on parameter '{inp_name}'. "
                    f"Injected script markup was stored and rendered by the application without sanitisation."
                    if is_stored
                    else f"{vuln_type} on parameter '{inp_name}'. Payload was echoed back unescaped and renders as executable markup in the browser."
                )
                findings.append(
                    {
                        "severity": "high",
                        "url": action,
                        "detail": vuln_desc,
                        "payload": payload,
                    }
                )
                break
            time.sleep(0.02)

    return findings
