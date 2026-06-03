from flask import Flask, request, jsonify
import threading
import time

app = Flask(__name__)

def run_background_job():
    time.sleep(1)
    print("job finished")

@app.route("/workers/start")
def start_workers():
    count = int(request.args.get("count", "1"))

    started = []
    for i in range(count):
        thread = threading.Thread(target=run_background_job)
        thread.start()
        started.append(thread.name)

    return jsonify({
        "started": len(started),
        "threads": started,
    })
