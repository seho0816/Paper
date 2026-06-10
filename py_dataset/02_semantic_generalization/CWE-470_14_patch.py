from flask import Flask, request, jsonify
import importlib

app = Flask(__name__)

# Define a whitelist of allowed modules and functions.
# This is crucial for preventing arbitrary code execution (CWE-470).
# Replace these with your actual application's allowed modules and functions
# that are designed to be exposed via this endpoint.
ALLOWED_JOB_MODULES = {
    "app_jobs": ["process_data", "generate_report"],
    # Add other allowed modules and their functions here, for example:
    # "data_processors": ["clean_database", "update_cache"],
}

def record_job_execution(module_name, function_name):
    print(f"running job: {module_name}.{function_name}")

@app.route("/jobs/run")
def run_job():
    module_name = request.args.get("module")
    function_name = request.args.get("function")

    # --- CWE-470 Fix: Validate module_name and function_name against a whitelist ---
    if not module_name or not function_name:
        return jsonify({"error": "Missing 'module' or 'function' parameter"}), 400

    if module_name not in ALLOWED_JOB_MODULES:
        return jsonify({"error": f"Module '{module_name}' is not allowed"}), 403

    if function_name not in ALLOWED_JOB_MODULES[module_name]:
        return jsonify({"error": f"Function '{function_name}' is not allowed in module '{module_name}'"}), 403
    # --- End CWE-470 Fix ---

    # Only record execution after successful validation
    record_job_execution(module_name, function_name)

    try:
        module = importlib.import_module(module_name)
        handler = getattr(module, function_name)
        result = handler()
    except ModuleNotFoundError:
        # This indicates a configuration issue where an allowed module does not exist.
        return jsonify({"error": f"Module '{module_name}' not found on server"}), 500
    except AttributeError:
        # This indicates a configuration issue where an allowed function does not exist within the module.
        return jsonify({"error": f"Function '{function_name}' not found in module '{module_name}'"}), 500
    except Exception as e:
        # Catch any other exceptions during function execution to prevent server errors
        return jsonify({"error": f"Error executing job: {str(e)}"}), 500

    return jsonify({
        "result": str(result),
    })
