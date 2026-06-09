from flask import Flask, request, Response

app = Flask(__name__)

def query_logs(limit):
    return [
        [str(i), "INFO", "sample log message"]
        for i in range(limit)
    ]

@app.route("/logs/export")
def export_logs():
    limit = int(request.args.get("limit", "100"))
    rows = query_logs(limit=limit)

    csv_lines = []
    for row in rows:
        csv_lines.append(",".join(row))

    return Response("\n".join(csv_lines), mimetype="text/csv")
