from flask import Flask, send_file, jsonify
from pathlib import Path

app = Flask(__name__)

BACKUP_DIR = "/var/backups/app"

def get_latest_backup_path():
    return str(Path(BACKUP_DIR) / "database.dump")

def build_audit_message(path):
    return {
        "target": path,
        "action": "download_backup",
    }

@app.route("/admin/backup/download")
def download_backup():
    backup_path = get_latest_backup_path()
    audit = build_audit_message(backup_path)
    print(audit)

    return send_file(backup_path, as_attachment=True)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
