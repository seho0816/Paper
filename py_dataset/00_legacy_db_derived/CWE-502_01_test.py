from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

def validate_state_shape(state):
    if not isinstance(state, dict):
        return False
    return "user_id" in state

@app.route("/session/restore", methods=["POST"])
def restore_session():
    raw_state = request.data

    session_state = pickle.loads(raw_state)

    if not validate_state_shape(session_state):
        return jsonify({"message": "invalid session state"}), 400

    return jsonify({
        "message": "session restored",
        "state": str(session_state),
    })
