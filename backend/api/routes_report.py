import json

from flask import Blueprint, jsonify, send_file

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