import json

from flask import Flask, request

app = Flask(__name__)


@app.post("/api/session/restore")
def restore_session():
    # CWE-502: Deserialization of Untrusted Data.
    # The original code used `pickle.loads`, which is highly dangerous when
    # deserializing data from untrusted sources, as it can lead to arbitrary code execution (RCE).
    # To mitigate this, `json.loads` is used instead. JSON deserialization is safe
    # as it only reconstructs basic data types (dictionaries, lists, strings, numbers, etc.)
    # and does not execute arbitrary code during deserialization.
    state = json.loads(
        request.data,
    )

    return {
        "state": str(state),
    }
