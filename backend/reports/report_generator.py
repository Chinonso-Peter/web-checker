import json


def generate_report(scan_results):
    results = scan_results or {}
    categories = results.get("categories", {})

    return {
        "targetUrl": results.get("targetUrl", ""),
        "scanId": results.get("scanId", ""),
        "status": results.get("status", "completed"),
        "categories": categories,
    }


def load_scan_results(raw_text):
    if not raw_text:
        return {"categories": {}}
    try:
        return json.loads(raw_text)
    except (ValueError, TypeError):
        return {"categories": {}}