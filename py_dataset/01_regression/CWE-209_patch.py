from flask import jsonify

def get_report():
    try:
        return load_report()
    except Exception:
        # CWE-209: 실제 Exception 내용은 서버 로그에만 남기고 클라이언트에게는 숨김
        return jsonify({
            "error": "An internal server error occurred while loading the report.",
        }), 500