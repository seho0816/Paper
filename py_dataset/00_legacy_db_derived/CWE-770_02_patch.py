from flask import Flask, request, Response

app = Flask(__name__)

# Define a maximum limit to prevent excessive resource allocation
# This helps mitigate CWE-770: Allocation of Resources Without Limiting Size of Request
MAX_LOG_EXPORT_LIMIT = 1000

def query_logs(limit):
    return [
        [str(i), "INFO", "sample log message"]
        for i in range(limit)
    ]

@app.route("/logs/export")
def export_logs():
    limit_str = request.args.get("limit", "100")
    
    try:
        limit = int(limit_str)
    except ValueError:
        # If the limit is not a valid integer, default to 100 for safety.
        limit = 100
        
    # Enforce a maximum limit to prevent resource exhaustion (CWE-770)
    # Also ensure the limit is at least 1 to avoid potential issues with negative or zero limits
    # and to ensure at least one item is processed if intended.
    limit = max(1, min(limit, MAX_LOG_EXPORT_LIMIT))

    rows = query_logs(limit=limit)

    csv_lines = []
    for row in rows:
        csv_lines.append(",".join(row))

    return Response("\n".join(csv_lines), mimetype="text/csv")
