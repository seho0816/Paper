import importlib.util
from pathlib import Path


TRUSTED_PLUGIN_DIR = Path(
    "/opt/application/plugins"
).resolve()


def load_report_plugin(
    plugin_name: str,
):
    if not plugin_name.isidentifier():
        raise ValueError(
            "invalid plugin name"
        )

    plugin_path = (
        TRUSTED_PLUGIN_DIR
        / f"{plugin_name}.py"
    ).resolve()

    plugin_path.relative_to(
        TRUSTED_PLUGIN_DIR
    )

    spec = importlib.util.spec_from_file_location(
        plugin_name,
        plugin_path,
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise ImportError(
            "plugin cannot be loaded"
        )

    module = importlib.util.module_from_spec(
        spec
    )
    spec.loader.exec_module(
        module
    )

    return module
