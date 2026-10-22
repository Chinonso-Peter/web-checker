"""Selenium-based crawler for JavaScript-heavy / SPA sites.

Selenium is optional at runtime: if a Chrome driver is unavailable this
module falls back to returning empty results so the scanner never crashes.
"""
import time

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from bs4 import BeautifulSoup

    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False


class SpaCrawler:
    def __init__(self, headless=True, timeout=3):
        self.headless = headless
        self.timeout = timeout
        self.target_url = None

    def set_target(self, url):
        self.target_url = url

    def crawl(self):
        if not SELENIUM_AVAILABLE or not self.target_url:
            return []

        options = ChromeOptions()
        if self.headless:
            options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-blink-features=AutomationControlled")

        try:
            driver = webdriver.Chrome(options=options)
        except Exception:
            return []

        forms = []
        try:
            driver.get(self.target_url)
            time.sleep(self.timeout)
            soup = BeautifulSoup(driver.page_source, "html.parser")
            for form in soup.find_all("form"):
                inputs = [
                    {"name": inp.get("name"), "type": inp.get("type", "text")}
                    for inp in form.find_all("input")
                    if inp.get("name")
                ]
                forms.append(
                    {
                        "action": form.get("action") or self.target_url,
                        "method": (form.get("method") or "get").lower(),
                        "inputs": inputs,
                    }
                )
        except Exception:
            pass
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        return forms