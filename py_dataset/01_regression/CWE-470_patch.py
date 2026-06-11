import importlib


# Define allowlists for plugin names and task names.
# Only modules and functions explicitly listed here will be allowed to be executed.
# In a real-world application, these lists should be securely managed,
# potentially loaded from a trusted configuration source.
ALLOWED_PLUGINS = {
    "my_safe_plugin_1",
    "my_safe_plugin_2",
    # Add all legitimate plugin module names here that this function is allowed to import.
}

ALLOWED_TASKS = {
    "run_job_a",
    "process_data_b",
    "execute_query",
    # Add all legitimate function names (tasks) that this function is allowed to call within allowed plugins.
}


def run_plugin(
    plugin_name: str,
    task_name: str,
):
    # Validate plugin_name against the allowlist to prevent arbitrary module imports.
    if plugin_name not in ALLOWED_PLUGINS:
        raise ValueError(f"Unauthorized plugin name: {plugin_name}")

    module = importlib.import_module(
        plugin_name
    )

    # Validate task_name against the allowlist to prevent arbitrary function calls.
    if task_name not in ALLOWED_TASKS:
        raise ValueError(f"Unauthorized task name: {task_name}")

    task = getattr(
        module,
        task_name,
    )

    return task()
