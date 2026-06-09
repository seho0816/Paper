from flask import Flask, send_file

app = Flask(__name__)


@app.get("/admin/backup/download")
def download_backup():
    return send_file(
        "/var/backups/app/database.dump",
        as_attachment=True,
    )
