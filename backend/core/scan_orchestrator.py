import time

from backend.core.auth_helper import resolve_target_cookies
from backend.core.crawler import Crawler
from backend.core.spa_crawler import SpaCrawler
from backend.scanners import (access_control_scanner, auth_scanner,
                              crypto_scanner, sqli_scanner, xss_scanner)

SCANNERS = [
    ("SQL Injection", sqli_scanner.scan),
    ("Cross-Site Scripting", xss_scanner.scan),
    ("Broken Access Control", access_control_scanner.scan),
    ("Cryptographic Failures", crypto_scanner.scan),
    ("Identification & Authentication", auth_scanner.scan),
]


def _dedupe(findings):
    """Collapse findings that are identical on URL + detail + severity."""
    seen = set()
    cleaned = []
    for finding in findings or []:
        key = (finding.get("url"), finding.get("detail"), finding.get("severity"))
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(finding)
    return cleaned


def run_scan(target_url, parameters=None, crawl_depth=1, cookies=None, headers=None):
    """
    Main Vulnerability Scan Orchestration Engine.
    
    Coordinates the full automated audit lifecycle:
    1. Authenticates against protected targets (e.g. DVWA session handshake) if cookies are omitted.
    2. Initializes and executes the HTTP Web Crawler to discover endpoints, forms, and input fields.
    3. Falls back to headless SPA crawling if client-side rendered JavaScript forms are detected.
    4. Consecutively executes the 5 OWASP vulnerability scanners:
       - SQL Injection (Error-based & Boolean Blind)
       - Cross-Site Scripting (Reflected, Stored, & DOM-based)
       - Broken Access Control (Unprotected Administrative Portals)
       - Cryptographic Failures (Plain HTTP, Missing HSTS, Insecure Cookies)
       - Identification & Authentication (Insecure Credential Transmissions)
    5. Deduplicates findings, isolates runtime scanner errors, and packages execution metrics.
    
    Args:
        target_url (str): Target web address to audit.
        parameters (list, optional): Specific parameter names to inject.
        crawl_depth (int): Maximum link recursion depth for the crawler.
        cookies (str/dict, optional): Session cookies for authenticated scanning.
        headers (str/dict, optional): Custom HTTP headers.
        
    Returns:
        dict: Compiled report payload containing categorized findings and duration.
    """
    start = time.time()

    # Step 1: Automatically resolve session cookies if targeting an authenticated environment like DVWA
    cookies = resolve_target_cookies(target_url, cookies=cookies)

    # Step 2: Initialize Web Crawler and map target application attack surface
    crawler = Crawler(max_depth=crawl_depth, cookies=cookies, headers=headers)
    crawler.set_target(target_url)
    forms = crawler.crawl()

    # Step 3: Fallback to SPA crawler if static HTML crawler finds no interactive forms
    if not forms:
        spa = SpaCrawler()
        spa.set_target(target_url)
        spa_forms = spa.crawl()
        if spa_forms:
            forms = spa_forms

    # Step 4: Dispatch test suite across all 5 registered OWASP scanner modules
    categories = {}
    for label, scanner_fn in SCANNERS:
        try:
            findings = scanner_fn(forms, target_url, parameters=parameters or None, cookies=cookies, headers=headers) or []
        except TypeError:
            findings = scanner_fn(forms, target_url, parameters=parameters or None) or []
        except Exception as exc:
            # Fault isolation: prevent a single scanner exception from aborting the entire audit
            findings = [
                {
                    "severity": "info",
                    "url": target_url,
                    "detail": f"Scanner error: {exc}",
                    "payload": None,
                }
            ]
        # Step 5: Deduplicate findings per category
        categories[label] = _dedupe(findings)

    # Step 6: Return structured audit report dictionary
    return {
        "targetUrl": target_url,
        "categories": categories,
        "durationSeconds": round(time.time() - start, 2),
    }