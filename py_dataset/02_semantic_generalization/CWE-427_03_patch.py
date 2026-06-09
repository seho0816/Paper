import os
import importlib
import importlib.util


def load_job_handler(
    working_directory: str,
):
    module_name = "job_handler"
    # Construct the full path to the module file.
    module_file_path = os.path.join(working_directory, f"{module_name}.py")

    # CWE-427 fix: Instead of modifying sys.path, directly load the module
    # from its file path using importlib.util. This prevents a malicious
    # 'working_directory' from injecting arbitrary modules into the Python
    # search path and overriding legitimate modules.
    spec = importlib.util.spec_from_file_location(module_name, module_file_path)

    if spec is None:
        # If spec_from_file_location returns None, it means the file could not
        # be found at the specified path or is not a valid module source.
        # Raise an error similar to what importlib.import_module would do.
        raise ModuleNotFoundError(f"Could not find or create module spec for '{module_file_path}'. "
                                  f"Ensure '{module_name}.py' exists in '{working_directory}'.")

    # Create a new module object from the specification.
    module = importlib.util.module_from_spec(spec)

    # Execute the module's code within its own namespace. This step makes
    # functions, classes, and variables defined in the module file available
    # in the 'module' object.
    if spec.loader:
        spec.loader.exec_module(module)
    else:
        # This case is highly unlikely for a spec created by spec_from_file_location
        # but is included for defensive programming.
        raise ImportError(f"No loader found for module '{module_name}' at '{module_file_path}'.")

    return module
