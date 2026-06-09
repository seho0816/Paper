import importlib
import sys
from dataclasses import dataclass
import os # Required for path manipulation
import importlib.util # Required for explicit module loading

@dataclass(frozen=True)
class ReportPlugin:
    search_path: str


class ReportPluginService:
    def activate(
        self,
        plugin: ReportPlugin,
    ):
        # CWE-427 fix: Prevent uncontrolled search path element.
        # Do not append untrusted paths to sys.path, as this affects global module resolution.
        # Instead, load the module directly from the specified path.

        # Resolve the plugin's search_path to an absolute path for safety and clarity.
        # This helps in preventing relative path ambiguities or simple directory traversal attempts.
        absolute_plugin_path = os.path.abspath(plugin.search_path)

        # Construct the full path to the module file.
        # The original code implies loading a module named "report_extension" from search_path.
        module_name = "report_extension"
        module_file_path = os.path.join(absolute_plugin_path, f"{module_name}.py")

        # Verify that the module file actually exists before attempting to load it.
        if not os.path.isfile(module_file_path):
            raise FileNotFoundError(f"Module file '{module_file_path}' not found at specified plugin search path.")

        # Create a module specification from the file location.
        spec = importlib.util.spec_from_file_location(module_name, module_file_path)

        if spec is None:
            # This handles cases where a spec cannot be created (e.g., not a valid Python module, or other issues).
            raise ImportError(f"Could not create module specification for '{module_name}' from '{module_file_path}'.")

        # Create a new module object based on the specification.
        module = importlib.util.module_from_spec(spec)

        # Execute the module's code to load its contents (functions, classes, variables) into the module object.
        spec.loader.exec_module(module)

        return module
