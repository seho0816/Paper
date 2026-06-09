from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/api/public/service-status")
def read_service_status():
    response = jsonify({
        "status": "available",
        "region": "ap-northeast-2",
    })

    response.headers["Access-Control-Allow-Origin"] = "*"

    return response
