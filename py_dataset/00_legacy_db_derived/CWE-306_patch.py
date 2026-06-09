from flask import Flask, send_file, jsonify, request, abort
from pathlib import Path
from functools import wraps

app = Flask(__name__)

BACKUP_DIR = "/var/backups/app"

# For CWE-306: Missing Authentication for Critical Function
# Add a simple authentication mechanism.
# In a real-world application, the API_KEY would be loaded from
# environment variables, a secure configuration service, or a vault,
# and a more robust authentication system (e.g., JWT, session-based login)
# would be used. This simple check demonstrates the introduction of an
# authentication barrier where none existed.
ADMIN_API_KEY = "your_strong_admin_api_key_here" # REPLACE_ME_WITH_A_SECURE_KEY

def require_admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-Admin-API-Key') == ADMIN_API_KEY:
            return f(*args, **kwargs)
        abort(401, description="Unauthorized: Missing or invalid X-Admin-API-Key")
    return decorated_function

def get_latest_backup_path():
    return str(Path(BACKUP_DIR) / "database.dump")

def build_audit_message(path):
    return {
        "target": path,
        "action": "download_backup",
    }

@app.route("/admin/backup/download")
@require_admin_auth # Apply the authentication decorator
def download_backup():
    backup_path = get_latest_backup_path()
    audit = build_audit_message(backup_path)
    print(audit)

    return send_file(backup_path, as_attachment=True)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
