import threading

from flask import request


def start_workers():
    count = int(
        request.args.get("count", "1")
    )

    for _ in range(count):
        threading.Thread(
            target=run_background_job,
        ).start()

    return "started"
