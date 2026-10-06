"""
Reports routes
"""
from flask import Blueprint, jsonify, Response
from ..services.report_service import report_service

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/reports/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    try:
        data = report_service.generate_report_data(scan_id)
        return jsonify({"status": "success", "report": data}), 200
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to generate report: {str(e)}"}), 500


@reports_bp.route('/reports/<int:scan_id>/html', methods=['GET'])
def get_report_html(scan_id):
    try:
        html = report_service.generate_html_report(scan_id)
        return Response(html, mimetype='text/html')
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to generate report HTML: {str(e)}"}), 500
