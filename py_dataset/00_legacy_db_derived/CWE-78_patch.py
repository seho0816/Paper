from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping_host():
    host = request.args.get("host")

    # CWE-78 Fix: Pass the command and its arguments as a list.
    # This prevents shell interpretation of user-supplied input in 'host'.
    # `shell=False` (which is the default) should be used, implicitly or explicitly.
    command_args = ["ping", "-c", "1", host]
    result = subprocess.check_output(command_args, text=True)

    return result
