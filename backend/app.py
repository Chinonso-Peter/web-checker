import logging
import os
import sys
import traceback

from flask import Flask, jsonify
from flask_cors import CORS

logger = logging.getLogger("web_checker")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.config import Config
from backend import db
from backend.database.db import init_db
from backend.api.routes_auth import auth_blueprint
from backend.api.routes_scan import scan_blueprint
from backend.api.routes_report import report_blueprint


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    init_db(app)
    CORS(app, supports_credentials=True)

    @app.errorhandler(400)
    def bad_request(err):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(err):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(err):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(err):
        logger.error("Unhandled error:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500

    app.register_blueprint(auth_blueprint, url_prefix="/api/auth")
    app.register_blueprint(scan_blueprint, url_prefix="/api/scan")
    app.register_blueprint(report_blueprint, url_prefix="/api/report")

    @app.route("/", methods=["GET"])
    def index():
        return jsonify(
            {
                "name": "Web Checker API",
                "endpoints": [
                    "POST /api/auth/register",
                    "POST /api/auth/login",
                    "GET  /api/auth/me",
                    "PATCH /api/auth/me",
                    "DELETE /api/auth/me",
                    "POST /api/auth/logout",
                    "POST /api/auth/forgot-password",
                    "POST /api/auth/forgot-username",
                    "POST /api/auth/reset-password",
                    "POST /api/auth/verify-email",
                    "POST /api/auth/resend-verification",
                    "POST /api/scan/start",
                    "GET  /api/scan/status/<scan_id>",
                    "GET  /api/scan/result/<scan_id>",
                    "GET  /api/report/generate/<scan_id>",
                    "GET  /api/report/pdf/<scan_id>",
                ],
            }
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, load_dotenv=False)