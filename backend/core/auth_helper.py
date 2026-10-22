import re
from urllib.parse import urlparse
import requests


def auto_dvwa_login(target_url):
    """
    Attempts automatic login to a local or remote DVWA (Damn Vulnerable Web Application) instance.
    Extracts the anti-CSRF user_token, logs in as admin/password, and sets security level to 'low'.
    """
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    login_url = f"{origin}/login.php"

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Web-Checker/1.0 (Security Scanner)"})
        resp = session.get(login_url, timeout=4)
        if resp.status_code != 200:
            return None

        # Confirm target is DVWA
        body = resp.text.lower()
        if "damn vulnerable web application" not in body and "dvwa" not in body:
            return None

        # Extract CSRF token
        token_m = re.search(r"user_token'\s*value='([a-f0-9]+)'", resp.text)
        token = token_m.group(1) if token_m else ""

        login_resp = session.post(
            login_url,
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=False,
            timeout=4,
        )

        phpsessid = session.cookies.get("PHPSESSID")
        if phpsessid:
            return f"PHPSESSID={phpsessid}; security=low"
    except Exception:
        pass
    return None


def resolve_target_cookies(target_url, cookies=None):
    """
    Ensures scans against authenticated targets (like DVWA) have active credentials.
    If cookies are provided, ensures 'security=low' is appended if omitted.
    If no cookies are provided and target is DVWA, auto-logs in and returns the session cookie.
    """
    if cookies and isinstance(cookies, str):
        if "phpsessid" in cookies.lower() and "security=" not in cookies.lower():
            return cookies.rstrip("; ") + "; security=low"
        return cookies

    # Check if target is a DVWA endpoint (explicit URL pattern or redirects to DVWA login)
    parsed = urlparse(target_url)
    is_dvwa_hint = (
        ":8080" in parsed.netloc
        or "dvwa" in target_url.lower()
        or "/vulnerabilities/" in target_url.lower()
    )

    if is_dvwa_hint:
        dvwa_cookie = auto_dvwa_login(target_url)
        if dvwa_cookie:
            return dvwa_cookie

    # Probe target endpoint to see if it redirects to DVWA login
    try:
        head_resp = requests.get(
            target_url,
            allow_redirects=False,
            timeout=3,
            headers={"User-Agent": "Web-Checker/1.0"},
        )
        if head_resp.status_code in (301, 302):
            loc = head_resp.headers.get("Location", "")
            if "login.php" in loc:
                dvwa_cookie = auto_dvwa_login(target_url)
                if dvwa_cookie:
                    return dvwa_cookie
    except Exception:
        pass

    return cookies
