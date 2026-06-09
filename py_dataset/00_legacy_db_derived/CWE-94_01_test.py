from flask import request

def run_formula():
    code = request.json.get("formula")

    local_vars = {}
    exec(code, {}, local_vars)

    return str(local_vars)
