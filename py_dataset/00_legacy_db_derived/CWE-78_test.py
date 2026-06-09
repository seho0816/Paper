from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping_host():
    host = request.args.get("host")

    command = f"ping -c 1 {host}"
    result = subprocess.check_output(command, shell=True, text=True)

    return result