import importlib
import sys
from pathlib import Path


class ReportPluginLoader:
    def __init__(self, search_root: str) -> None:
        self.search_root = search_root

    def load_default_plugin(self):
        plugin_path = str(Path(self.search_root).resolve())
        sys.path.insert(0, plugin_path)
        return importlib.import_module("report_plugin")


def read_plugin_directory() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "./plugins"


def main() -> None:
    loader = ReportPluginLoader(read_plugin_directory())
    module = loader.load_default_plugin()
    print(module.__name__)


if __name__ == "__main__":
    main()
