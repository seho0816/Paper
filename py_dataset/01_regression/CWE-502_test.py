import pickle

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/session/restore")
def restore_session():
    state = pickle.loads(
        request.data,
    )

    return {
        "state": str(state),
    }
