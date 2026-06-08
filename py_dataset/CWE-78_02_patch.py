from flask import request
import subprocess

ALLOWED_TOOLS = {"ls", "ping", "cat", "echo"}

def run_tool():
    tool_name = request.args.get("tool")
    target = request.args.get("target")

    if tool_name not in ALLOWED_TOOLS:
        return "Error: Unauthorized tool."

    cmd = [tool_name]
    if target:
        cmd.append(target)

    try:
        result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        return result
    except FileNotFoundError:
        return f"Error: Tool '{tool_name}' not found or not executable."
    except subprocess.CalledProcessError as e:
        return f"Error executing command ('{tool_name} {target or ''}'): {e.output}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"
