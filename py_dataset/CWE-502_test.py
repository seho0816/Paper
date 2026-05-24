import base64
import pickle
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('echo "Compromised!"',))

@app.route("/api/load-state", methods=["POST"])
def load_state():
    encoded_state = request.json.get("state")
    raw_state = base64.b64decode(encoded_state)
    state = pickle.loads(raw_state)

    return jsonify({
        "state": str(state)
    })