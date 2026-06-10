import importlib
import sys
from pathlib import Path
import importlib.util


class ReportPluginLoader:
    def __init__(self, search_root: str) -> None:
        self.search_root = search_root

    def load_default_plugin(self):
        # Resolve the plugin directory to an absolute path.
        plugin_dir = Path(self.search_root).resolve()
        # Construct the full path to the specific plugin file.
        plugin_file = plugin_dir / "report_plugin.py"

        # Verify the plugin file exists to provide clearer error messages.
        if not plugin_file.is_file():
            raise FileNotFoundError(f"Plugin file not found: {plugin_file}")

        # Create a module specification from the file location.
        # This method loads the module directly from the specified file path
        # without modifying sys.path, thereby mitigating CWE-427.
        spec = importlib.util.spec_from_file_location("report_plugin", plugin_file)

        if spec is None:
            raise ImportError(f"Could not create module specification for {plugin_file}")

        # Create a new module based on the specification.
        module = importlib.util.module_from_spec(spec)

        # Execute the module's code within its own namespace.
        # This effectively imports the module.
        if spec.loader: # spec.loader can be None in some edge cases for non-file-based specs
            spec.loader.exec_module(module)
        else:
            raise ImportError(f"No loader found for module spec {spec.name}")

        return module


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
