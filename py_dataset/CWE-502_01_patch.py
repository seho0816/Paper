from flask import Flask, request, jsonify
import json

app = Flask(__name__)

def validate_state_shape(state):
    if not isinstance(state, dict):
        return False
    return "user_id" in state

@app.route("/session/restore", methods=["POST"])
def restore_session():
    raw_state = request.data

    try:
        # CWE-502 fix: Replaced pickle.loads with json.loads to prevent arbitrary code execution
        # from untrusted deserialized data.
        # It's assumed that clients will now send JSON formatted data.
        session_state = json.loads(raw_state)
    except json.JSONDecodeError:
        return jsonify({"message": "invalid JSON format"}), 400
    except Exception:
        # Catch any other unexpected errors during JSON parsing
        return jsonify({"message": "failed to parse session data"}), 400

    if not validate_state_shape(session_state):
        return jsonify({"message": "invalid session state"}), 400

    return jsonify({
        "message": "session restored",
        "state": str(session_state),
    })
