import importlib
import sys
from dataclasses import dataclass
import importlib.util


@dataclass(frozen=True)
class PluginRequest:
    plugin_directory: str


class PluginLoader:
    def load(
        self,
        request: PluginRequest,
    ):
        # CWE-427 fix: Removed the vulnerable line that globally modifies sys.path.
        # sys.path.insert(0, request.plugin_directory)

        # Safely load the module by explicitly restricting the search path
        # to the requested plugin_directory for this specific import operation.
        # This prevents an attacker from inserting a malicious directory into the global sys.path.
        spec = importlib.util.find_spec("company_plugin", path=[request.plugin_directory])

        if spec is None:
            # If the module cannot be found within the specified directory,
            # raise an error consistent with the original importlib.import_module behavior.
            raise ModuleNotFoundError(f"No module named 'company_plugin' found in '{request.plugin_directory}'")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
