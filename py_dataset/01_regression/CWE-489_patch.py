from flask import Flask


app = Flask(__name__)


def start_server() -> None:
    app.run(
        host='127.0.0.1',
        port=8080,
        debug=False,
    )
