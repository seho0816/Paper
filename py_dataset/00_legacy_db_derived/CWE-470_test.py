from flask import Flask, request, jsonify
import importlib

app = Flask(__name__)

def record_job_execution(module_name, function_name):
    print(f"running job: {module_name}.{function_name}")

@app.route("/jobs/run")
def run_job():
    module_name = request.args.get("module")
    function_name = request.args.get("function")

    record_job_execution(module_name, function_name)

    module = importlib.import_module(module_name)
    handler = getattr(module, function_name)
    result = handler()

    return jsonify({
        "result": str(result),
    })
