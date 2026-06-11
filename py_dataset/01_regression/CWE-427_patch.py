import importlib.util
import os
import sys


def load_report_plugin(
    plugin_dir: str,
):
    plugin_file_path = os.path.join(plugin_dir, "report_plugin.py")
    plugin_file_path = os.path.abspath(plugin_file_path)

    if not os.path.isfile(plugin_file_path):
        raise FileNotFoundError(
            f"Plugin module 'report_plugin.py' not found at {plugin_file_path}"
        )

    spec = importlib.util.spec_from_file_location("report_plugin", plugin_file_path)

    if spec is None:
        raise ImportError(f"Could not create module specification for {plugin_file_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    sys.modules["report_plugin"] = module

    return module
