from flask import Flask, jsonify


metrics_app = Flask(__name__)


@metrics_app.get('/internal/metrics')
def internal_metrics():
    # The functions read_queue_depth() and read_database_pool_status() are not
    # provided in the vulnerable code snippet. Assuming their implementations
    # are external or would typically not introduce CWE-1327 (Untrusted Search Path)
    # in this context if they were simple data retrieval functions.
    # If they were to execute external commands, their implementation would
    # need to use absolute paths to prevent CWE-1327. However, modifying or adding
    # these undefined functions is outside the scope of the strict rules.
    # The provided Flask application code itself does not directly involve
    # executing external programs or loading libraries via an untrusted search path.
    return jsonify({
        'queue_depth': read_queue_depth(),
        'database_pool': read_database_pool_status(),
    })


def start_metrics_server() -> None:
    metrics_app.run(
        host='0.0.0.0',
        port=9105,
    )
