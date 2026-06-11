from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/api/public/service-status")
def read_service_status():
    response = jsonify({
        "status": "available",
        "region": "ap-northeast-2",
    })

    # CWE-942 (Permissive Cross-domain Policy with Untrusted Domains) fix:
    # Removed the overly permissive 'Access-Control-Allow-Origin: *' header.
    # If specific cross-origin access is required, define explicit trusted origins
    # instead of allowing all with '*'. By default, the browser's Same-Origin Policy applies.

    return response
