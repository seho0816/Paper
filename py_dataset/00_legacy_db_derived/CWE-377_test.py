from flask import Flask, request, jsonify
import tempfile
from pathlib import Path

app = Flask(__name__)

def render_html_template(html):
    header = "<!doctype html><html><body>"
    footer = "</body></html>"
    return header + html + footer

def write_report_to_temp(rendered_html):
    temp_path = tempfile.mktemp(prefix="report_", suffix=".html")

    with open(temp_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    return temp_path

@app.route("/report/render", methods=["POST"])
def render_report():
    html = request.form.get("html", "")
    rendered_html = render_html_template(html)

    temp_path = write_report_to_temp(rendered_html)

    return jsonify({
        "message": "report rendered",
        "path": temp_path,
        "exists": Path(temp_path).exists(),
    })
