from flask import Flask, request, jsonify
import threading
import time

app = Flask(__name__)

# Define a maximum limit for the number of workers to prevent resource exhaustion (CWE-770)
MAX_WORKER_COUNT = 50

def run_background_job():
    time.sleep(1)
    print("job finished")

@app.route("/workers/start")
def start_workers():
    try:
        # Attempt to convert 'count' to an integer.
        # This handles the default value if 'count' is not provided.
        count = int(request.args.get("count", "1"))
    except ValueError:
        # If 'count' is not a valid integer, return an error.
        # This prevents an unhandled exception (server crash) which is a form of Denial of Service.
        return jsonify({"error": "Invalid 'count' parameter. Must be an integer."}), 400

    # CWE-770 fix: Ensure the requested 'count' does not exceed the defined maximum.
    # This prevents an attacker from requesting an excessive number of threads,
    # leading to resource exhaustion (CPU, memory, thread limits) and Denial of Service.
    if count > MAX_WORKER_COUNT:
        return jsonify({"error": f"Cannot start more than {MAX_WORKER_COUNT} workers at once."}), 400

    started = []
    # If count is 0 or negative, range(count) will produce an empty sequence,
    # so no threads will be created, which is safe and does not lead to resource exhaustion.
    for i in range(count):
        thread = threading.Thread(target=run_background_job)
        thread.start()
        started.append(thread.name)

    return jsonify({
        "started": len(started),
        "threads": started,
    })
