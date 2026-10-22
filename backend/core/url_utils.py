import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

def normalize_url(url: str) -> str:
    """Basic URL normalization: lower-case host, sort query params, strip fragments."""
    parsed = urlparse(url)
    # lower-case scheme and netloc
    scheme = (parsed.scheme or "http").lower()
    netloc = (parsed.netloc or "").lower()
    # strip fragment
    path = parsed.path or "/"
    query = parsed.query or ""
    # sort query params
    params = parse_qs(query)
    sorted_query = urlencode(params, doseq=True)
    # reconstruct
    return urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))

def is_valid_url(url: str) -> bool:
    """Basic check: must have a scheme and netloc."""
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def join_url(base: str, url: str) -> str:
    """Combine base URL with relative URL."""
    from urllib.parse import urljoin
    return urljoin(base, url)