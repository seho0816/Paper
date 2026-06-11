import importlib.util
import importlib.machinery


def load_zipped_extension(
    archive_path: str,
):
    # CWE-427: Uncontrolled Search Path Element
    # The original code directly inserts `archive_path` into `sys.path`,
    # which is a global search path. If `archive_path` is untrusted,
    # an attacker could inject malicious modules.
    #
    # Fix: Instead of modifying the global `sys.path`,
    # use `importlib.machinery.PathFinder.find_spec` with a controlled
    # `path` argument to search for the module only within the specified `archive_path`.
    # This prevents the untrusted path from influencing other imports
    # and keeps the search path confined to the intended location for this operation.
    spec = importlib.machinery.PathFinder.find_spec("extension", path=[archive_path])

    if spec is None:
        raise ModuleNotFoundError(f"Module 'extension' not found in '{archive_path}'")

    module = importlib.util.module_from_spec(spec)
    if spec.loader:
        spec.loader.exec_module(module)
    else:
        # Fallback or error if loader is missing, though unlikely for found specs.
        raise ImportError(f"Could not load module 'extension' from '{archive_path}': no loader found.")

    return module
