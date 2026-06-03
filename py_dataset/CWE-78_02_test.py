from flask import request
import subprocess

def run_tool():
    tool = request.args.get("tool")
    target = request.args.get("target")

    result = subprocess.check_output([tool, target])

    return result.decode("utf-8")
