import importlib


def run_plugin(
    plugin_name: str,
    task_name: str,
):
    module = importlib.import_module(
        plugin_name
    )
    task = getattr(
        module,
        task_name,
    )

    return task()
