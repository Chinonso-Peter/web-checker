import json
import uuid

from flask import Blueprint, g, request, jsonify

from backend import db
from backend.auth import login_required
from backend.models.scan import Scan
from backend.utils.sanitize import sanitize_input, sanitize_url

scan_blueprint = Blueprint("scan", __name__)

MAX_PARAMETERS = 20


def _parse_parameters(raw):
    if isinstance(raw, list):
        parts = raw
    elif isinstance(raw, str):
        parts = raw.split(",")
    else:
        parts = []
    names = [str(p).strip() for p in parts if str(p).strip()]
    return names[:MAX_PARAMETERS]


@scan_blueprint.route("/start", methods=["POST"])
@login_required
def start_scan():
    """
    Scan Initiation API Endpoint.
    
    Accepts target parameters from the frontend and launches an audit:
    1. Validates and sanitizes the target URL (enforces http/https schemes).
    2. Parses, cleans, and bounds user-supplied injection parameter targets.
    3. Resolves and sanitizes session cookies and custom authentication headers.
    4. Creates a persistent Scan record with unique UUID in 'running' state.
    5. Hands off execution to the core scan orchestrator.
    6. Commits completed audit results to the database and returns JSON summary.
    """
    data = request.get_json(silent=True) or {}
    
    # Step 1: Validate and sanitize target URL
    raw_url = (data.get("targetUrl") or "").strip()
    if raw_url and not raw_url.lower().startswith(("http://", "https://")):
        if raw_url.lower().startswith(("localhost", "127.0.0.1")):
            raw_url = f"http://{raw_url}"
        else:
            raw_url = f"https://{raw_url}"

    try:
        target_url = sanitize_input(raw_url, "url")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    if not target_url:
        return jsonify({"error": "targetUrl is required and must be a valid domain or web address"}), 400

    # Step 2: Sanitize parameter list (bounds maximum injection points to 20)
    raw_params = data.get("parameters", [])
    if isinstance(raw_params, list):
        parts = raw_params
    elif isinstance(raw_params, str):
        parts = raw_params.split(",")
    else:
        parts = []
    
    parameters = []
    for p in parts:
        if not p:
            continue
        try:
            param = sanitize_input(str(p).strip(), "text", max_length=100)
            if param:
                parameters.append(param)
        except ValueError:
            continue
    
    parameters = parameters[:20]

    # Step 3: Sanitize cookies & custom headers (support for DVWA and authenticated apps)
    raw_cookies = data.get("cookies", "")
    cookies = None
    if raw_cookies and isinstance(raw_cookies, str):
        try:
            cookies = sanitize_input(raw_cookies, "text", max_length=2048)
        except ValueError:
            cookies = None

    from backend.core.auth_helper import resolve_target_cookies
    cookies = resolve_target_cookies(target_url, cookies=cookies)

    raw_headers = data.get("headers", "")
    headers = None
    if raw_headers and isinstance(raw_headers, str):
        try:
            headers = sanitize_input(raw_headers, "text", max_length=2048)
        except ValueError:
            headers = None

    # Step 4: Persist scan record in database bound to authenticated user
    scan = Scan(
        scanId=str(uuid.uuid4()),
        targetUrl=target_url,
        status="running",
        progress=0,
        parameters=json.dumps(parameters) if parameters else None,
        cookies=cookies,
        headers=headers,
        userId=g.current_user.userId,
    )
    db.session.add(scan)
    db.session.commit()

    # Step 5: Execute security audit via orchestrator engine
    from backend.core.scan_orchestrator import run_scan

    try:
        results = run_scan(target_url, parameters=parameters, cookies=cookies, headers=headers)
        scan.status = "completed"
        scan.progress = 100
        scan.results = json.dumps(results)
    except Exception as exc:
        scan.status = "failed"
        scan.results = json.dumps({"error": str(exc)})
    db.session.commit()
    db.session.refresh(scan)

    # Step 6: Return scan summary payload
    payload = {"scanId": scan.scanId, "targetUrl": scan.targetUrl, "status": scan.status}
    if parameters:
        payload["parameters"] = parameters
    if scan.status == "completed":
        payload["categories"] = json.loads(scan.results).get("categories", {})
    return jsonify(payload), (202 if scan.status == "running" else 200)


@scan_blueprint.route("/status/<scan_id>", methods=["GET"])
@login_required
def status(scan_id):
    scan = Scan.query.filter_by(scanId=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    resp = scan.to_dict()
    if scan.status == "failed":
        resp["error"] = json.loads(scan.results or "{}").get("error", "Scan failed")
    return jsonify(resp), 200


@scan_blueprint.route("/result/<scan_id>", methods=["GET"])
@login_required
def result(scan_id):
    scan = Scan.query.filter_by(scanId=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": "Scan not completed"}), 409
    data = json.loads(scan.results or "{}")
    return jsonify(
        {"scanId": scan.scanId, "targetUrl": scan.targetUrl, "categories": data.get("categories", {})}
    ), 200