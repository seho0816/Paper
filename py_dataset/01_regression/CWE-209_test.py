import traceback

from flask import jsonify


def get_report():
    try:
        return load_report()
    except Exception as error:
        return jsonify({
            "error": str(error),
            "trace": traceback.format_exc(),
        }), 500
