"""
ECDAT Demo API Application.

Flask application establishing the presentation/API boundary above the DemoOrchestrator.
Exposes minimal endpoints for scenario selection and real core execution.
"""

from pathlib import Path
from typing import Any, Dict, Optional
from flask import Flask, jsonify, request, send_from_directory

from demo.adapters.registry import DemoAdapterRegistry
from demo.orchestration.engine import DemoOrchestrator
from demo.scenarios.registry import ScenarioRegistry


def create_app(
    orchestrator: Optional[DemoOrchestrator] = None,
    frontend_dir: Optional[Path] = None,
) -> Flask:
    """Application factory for the ECDAT Demo API."""
    app = Flask(__name__, static_folder=None)
    orch = orchestrator or DemoOrchestrator()
    static_root = frontend_dir or (Path(__file__).resolve().parent.parent / "frontend")

    # 1. Health check & runtime classification
    @app.route("/api/health", methods=["GET"])
    def get_health() -> Any:
        return jsonify({
            "status": "healthy",
            "service": "ECDAT Demo API",
            "version": "0.3.0-d3",
            "phase": "Phase D3 — Complete Working Demo",
            "core_status": "CONNECTED_FROZEN",
            "classifications": {
                "LIVE": "Real frozen ECDAT analytical core in product/core/ consumed directly.",
                "CONTROLLED_DEMO": "Scenarios driven by ground-truth benchmark fixtures in product/benchmark/.",
                "ARCHITECTURAL": "Future discovery adapters (Sonar, CodeQL, sslscan) documented but not live.",
            },
        })

    # 2. List available controlled scenarios
    @app.route("/api/scenarios", methods=["GET"])
    def list_scenarios() -> Any:
        scenarios = orch.scenario_registry.list_scenarios()
        return jsonify({
            "count": len(scenarios),
            "scenarios": [s.to_dict() for s in scenarios],
        })

    # 3. List discovery adapters and capability classification
    @app.route("/api/adapters", methods=["GET"])
    def list_adapters() -> Any:
        adapters = orch.adapter_registry.list_adapters()
        return jsonify({
            "count": len(adapters),
            "adapters": [a.to_dict() for a in adapters],
        })

    # 4. Execute a controlled scenario through real core
    @app.route("/api/scenarios/<scenario_id>/run", methods=["GET", "POST"])
    def run_scenario(scenario_id: str) -> Any:
        if request.method != "POST":
            return jsonify({"error": "Method not allowed"}), 405
        result = orch.run_scenario(scenario_id=scenario_id)
        http_code = 200
        if result.status.value == "FAILED":
            http_code = 500
        elif result.status.value == "UNAVAILABLE":
            http_code = 404
        return jsonify(result.to_dict()), http_code

    # 5. Download official demo sample project zip
    @app.route("/api/sample-project/download", methods=["GET"])
    def download_sample_project() -> Any:
        sample_zip = Path(__file__).resolve().parent.parent / "sample_project" / "ECDAT-Demo-Application.zip"
        if not sample_zip.exists():
            return jsonify({"error": "Sample project zip not found"}), 404
        return send_from_directory(
            str(sample_zip.parent),
            sample_zip.name,
            as_attachment=True,
            download_name="ECDAT-Demo-Application.zip",
            mimetype="application/zip",
        )

    # 6. Analyze demo project or uploaded demonstration files through bounded discovery
    @app.route("/api/demo-project/analyze", methods=["POST"])
    def analyze_demo_project() -> Any:
        use_sample = (
            request.args.get("sample", "").lower() in ("true", "1")
            or request.form.get("use_sample", "").lower() in ("true", "1")
        )

        file_bytes = None
        filename = None
        if "file" in request.files:
            uploaded_file = request.files["file"]
            if uploaded_file and uploaded_file.filename:
                filename = uploaded_file.filename
                file_bytes = uploaded_file.read()

        # Reject empty analysis requests when no file is uploaded and sample was not explicitly requested
        if (file_bytes is None or len(file_bytes) == 0) and not use_sample:
            return jsonify({
                "error": "Add a demonstration project to begin. No file provided.",
                "status": "VALIDATION_ERROR",
            }), 400

        result = orch.run_demo_project(file_bytes=file_bytes, filename=filename, use_sample=use_sample)
        http_code = 200
        if result.status.value == "FAILED":
            if result.error_message and "not a valid or readable ZIP file" in result.error_message:
                http_code = 400
            else:
                http_code = 500
        elif result.status.value == "UNAVAILABLE":
            http_code = 400
        return jsonify(result.to_dict()), http_code

    # 5. Serve minimal frontend shell
    @app.route("/", methods=["GET"])
    def serve_index() -> Any:
        if static_root.exists() and (static_root / "index.html").exists():
            return send_from_directory(str(static_root), "index.html")
        return jsonify({"message": "ECDAT Demo API running. Frontend static root not found."})

    @app.route("/<path:filename>", methods=["GET"])
    def serve_static(filename: str) -> Any:
        if filename.startswith("api/"):
            return jsonify({"error": "Resource not found"}), 404
        try:
            resolved_target = (static_root / filename).resolve()
            if not resolved_target.is_relative_to(static_root.resolve()):
                return jsonify({"error": "Resource not found"}), 404
            if resolved_target.is_file():
                return send_from_directory(str(static_root), filename)
        except Exception:
            return jsonify({"error": "Resource not found"}), 404
        return jsonify({"error": "File not found"}), 404

    # 6. Global error handlers (JSON-safe, no traceback disclosure)
    @app.errorhandler(404)
    def handle_404(e: Any) -> Any:
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(405)
    def handle_405(e: Any) -> Any:
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def handle_500(e: Any) -> Any:
        return jsonify({"error": "Internal server error"}), 500

    @app.after_request
    def set_cache_headers(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    return app
