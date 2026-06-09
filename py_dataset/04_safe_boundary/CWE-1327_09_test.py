from flask import Flask


metrics_app = Flask(__name__)


def start_metrics_server() -> None:
    metrics_app.run(
        host='127.0.0.1',
        port=9105,
    )
