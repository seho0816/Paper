from pathlib import Path

from flask import Flask, request

app = Flask(__name__)

REPORT_ROOT = Path("/srv/reports")


@app.get("/api/reports/content")
def read_report():
    report_name = request.args.get("name", "")
    report_path = REPORT_ROOT / report_name

    return report_path.read_text(
        encoding="utf-8",
    )
