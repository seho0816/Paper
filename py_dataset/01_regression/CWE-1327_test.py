from flask import Flask, jsonify


metrics_app = Flask(__name__)


@metrics_app.get('/internal/metrics')
def internal_metrics():
    return jsonify({
        'queue_depth': read_queue_depth(),
        'database_pool': read_database_pool_status(),
    })


def start_metrics_server() -> None:
    metrics_app.run(
        host='0.0.0.0',
        port=9105,
    )
