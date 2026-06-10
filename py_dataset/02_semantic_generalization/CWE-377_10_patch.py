from flask import Flask, request, jsonify
import tempfile
from pathlib import Path
import os # Added for os.fdopen and os.close (if needed, os.fdopen handles closing)

app = Flask(__name__)

def render_html_template(html):
    header = "<!doctype html><html><body>"
    footer = "</body></html>"
    return header + html + footer

def write_report_to_temp(rendered_html):
    # CWE-377 Fix: Use tempfile.mkstemp() instead of tempfile.mktemp().
    # mkstemp creates the file securely and returns a file descriptor and the path.
    fd, temp_path = tempfile.mkstemp(prefix="report_", suffix=".html")

    # Use os.fdopen to open the file securely using the file descriptor.
    # This avoids a race condition between creating the name and opening the file.
    with os.fdopen(fd, "w", encoding="utf-8") as f:
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
