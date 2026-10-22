from urllib.parse import urlparse

from backend.core.request_handler import RequestHandler


def scan(forms, target_url, parameters=None, cookies=None, headers=None, **kwargs):
    findings = []
    handler = RequestHandler(cookies=cookies, headers=headers)
    parsed = urlparse(target_url)

    if parsed.scheme != "https":
        findings.append(
            {
                "severity": "high",
                "url": target_url,
                "detail": (
                    "Target is served over plain HTTP. Sensitive data transmitted "
                    "in transit can be read or modified (cryptographic failure)."
                ),
                "payload": None,
            }
        )
    # Missing-HSTS warnings are meaningless outside HTTPS, so skip that check for
    # HTTP targets, but cookie flags are still observable and reported below.

    resp = handler.get(target_url)
    if resp is None:
        return findings

    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

    if parsed.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(
            {
                "severity": "low",
                "url": target_url,
                "detail": "Missing Strict-Transport-Security (HSTS) header.",
                "payload": None,
            }
        )

    cookies = list(getattr(resp, "cookies", []) or [])
    if cookies:
        def _cookie_flags(c):
            try:
                http_only = c.has_nonstandard_attr("HttpOnly")
                secure = bool(getattr(c, "secure", False))
                return secure, http_only
            except Exception:
                return False, False

        fully_insecure = []
        partially_insecure = []
        for c in cookies:
            secure, http_only = _cookie_flags(c)
            if not secure and not http_only:
                fully_insecure.append(c)
            elif not (secure and http_only):
                partially_insecure.append(c)

        if fully_insecure:
            names = ", ".join(sorted({c.name for c in fully_insecure}))
            findings.append(
                {
                    "severity": "medium",
                    "url": target_url,
                    "detail": (
                        f"Cookie(s) ['{names}'] set WITHOUT Secure and HttpOnly "
                        "flags, exposing them to interception and script access."
                    ),
                    "payload": None,
                }
            )
        elif partially_insecure:
            names = ", ".join(sorted({c.name for c in partially_insecure}))
            findings.append(
                {
                    "severity": "low",
                    "url": target_url,
                    "detail": (
                        f"Cookie(s) ['{names}'] missing one of the Secure or "
                        "HttpOnly flags."
                    ),
                    "payload": None,
                }
            )

    return findings