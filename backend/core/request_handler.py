import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

class RequestHandler:
    def __init__(self, timeout=10, max_redirects=5, cookies=None, headers=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Web-Checker/1.0 (Educational Tool)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        if cookies:
            self.set_cookies(cookies)
        if headers:
            self.set_headers(headers)

    def set_cookies(self, cookies):
        """Set cookies from a dict or a cookie string (e.g. 'PHPSESSID=...; security=low')."""
        if not cookies:
            return
        if isinstance(cookies, dict):
            self.session.cookies.update(cookies)
        elif isinstance(cookies, str):
            for item in cookies.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    def set_headers(self, headers):
        """Set headers from a dict or multiline key: value string."""
        if not headers:
            return
        if isinstance(headers, dict):
            self.session.headers.update(headers)
        elif isinstance(headers, str):
            for line in headers.strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    self.session.headers[k.strip()] = v.strip()

    def get(self, url, **kwargs):
        try:
            resp = self.session.get(url, timeout=self.timeout, **kwargs)
            return resp
        except (Timeout, ConnectionError):
            return None
        except RequestException as e:
            return None

    def post(self, url, data=None, **kwargs):
        try:
            resp = self.session.post(url, data=data, timeout=self.timeout, **kwargs)
            return resp
        except (Timeout, ConnectionError):
            return None
        except RequestException:
            return None

    def set_header(self, key, value):
        self.session.headers[key] = value

    def clear_cookies(self):
        self.session.cookies.clear()
