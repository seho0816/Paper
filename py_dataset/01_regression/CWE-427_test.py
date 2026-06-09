import importlib
import sys


def load_report_plugin(
    plugin_dir: str,
):
    sys.path.insert(
        0,
        plugin_dir,
    )

    return importlib.import_module(
        "report_plugin"
    )
