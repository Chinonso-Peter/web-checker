import json

from flask import Blueprint, g, jsonify, send_file

from backend.auth import login_required
from backend.models.scan import Scan
from backend.reports.pdf_export import export_pdf

report_blueprint = Blueprint("report", __name__)


def _load_scan(scan_id):
    scan = Scan.query.filter_by(scanId=scan_id).first()
    if not scan:
        return None, jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return None, scan.to_dict(), (
            jsonify({"error": "Scan not completed", "status": scan.status}), 409
        )[0]
    return scan, jsonify({}), 200


@report_blueprint.route("/history", methods=["GET"])
@login_required
def list_history():
    """Returns the authenticated user's scan history and summary metrics."""
    user_id = g.current_user.userId
    scans = Scan.query.filter_by(userId=user_id).order_by(Scan.created_at.desc()).all()
    history = []
    for s in scans:
        findings_count = 0
        highest_severity = "none"
        if s.results:
            try:
                res = json.loads(s.results)
                cats = res.get("categories", {})
                for f_list in cats.values():
                    if isinstance(f_list, list):
                        findings_count += len(f_list)
                        for item in f_list:
                            sev = item.get("severity", "info").lower()
                            if sev == "critical":
                                highest_severity = "critical"
                            elif sev == "high" and highest_severity not in ("critical",):
                                highest_severity = "high"
                            elif sev == "medium" and highest_severity not in ("critical", "high"):
                                highest_severity = "medium"
                            elif sev == "low" and highest_severity not in ("critical", "high", "medium"):
                                highest_severity = "low"
            except Exception:
                pass

        history.append({
            "scanId": s.scanId,
            "targetUrl": s.targetUrl,
            "status": s.status,
            "progress": s.progress,
            "findingsCount": findings_count,
            "highestSeverity": highest_severity,
            "createdAt": s.created_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(s, "created_at", None) else None,
        })
    return jsonify({"scans": history}), 200


@report_blueprint.route("/generate/<scan_id>", methods=["GET"])
@login_required
def generate(scan_id):
    scan = Scan.query.filter_by(scanId=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": "Scan not completed", "status": scan.status}), 409

    results = json.loads(scan.results or "{}")
    payload = {
        "scanId": scan.scanId,
        "targetUrl": scan.targetUrl,
        "status": scan.status,
        "parameters": json.loads(scan.parameters) if scan.parameters else None,
        "categories": results.get("categories", {}),
        "createdAt": scan.created_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(scan, "created_at", None) else None,
    }
    return jsonify(payload), 200


@report_blueprint.route("/pdf/<scan_id>", methods=["GET"])
@login_required
def pdf(scan_id):
    scan = Scan.query.filter_by(scanId=scan_id).first()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": "Scan not completed", "status": scan.status}), 409

    results = json.loads(scan.results or "{}")
    report_data = {
        "targetUrl": scan.targetUrl,
        "scanId": scan.scanId,
        "createdAt": scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if getattr(scan, "created_at", None) else None,
        "categories": results.get("categories", {}),
    }
    pdf_bytes = export_pdf(report_data)
    return send_file(
        pdf_bytes,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"web_checker_report_{scan.scanId}.pdf",
    )
