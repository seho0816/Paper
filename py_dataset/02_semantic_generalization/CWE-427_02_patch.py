import importlib
import os
import sys
import importlib.util


def load_extension():
    extension_path = os.environ["EXTENSION_PATH"]

    # CWE-427 fix: Do not modify sys.path directly with an uncontrolled path.
    # Instead, use importlib.util.find_spec to explicitly search for the module
    # within the specified 'extension_path' only. This prevents arbitrary
    # directories from affecting the global Python module search path.
    spec = importlib.util.find_spec("application_extension", path=[extension_path])

    if spec is None:
        # The original importlib.import_module would raise an ImportError
        # if the module cannot be found. This mirrors that behavior.
        raise ImportError(f"Could not find module 'application_extension' in '{extension_path}'")

    # Create a new module object based on the specification
    module = importlib.util.module_from_spec(spec)

    # Execute the module's code within the newly created module object
    spec.loader.exec_module(module)

    # Add the module to sys.modules, mimicking the behavior of importlib.import_module.
    # This ensures that subsequent imports of "application_extension" will retrieve
    # this already loaded module without re-executing its code.
    sys.modules["application_extension"] = module

    return module
