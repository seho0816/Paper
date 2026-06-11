import importlib
import sys
import os


def resolve_load_plugin(
    _root,
    _info,
    plugin_path: str,
) -> dict:
    # --- CWE-427: Uncontrolled Search Path Element fix start ---
    # The vulnerability lies in adding an arbitrary, uncontrolled 'plugin_path'
    # to sys.path, allowing potential loading of malicious modules.
    # To fix this, we must validate 'plugin_path' against a trusted base directory.

    # 1. Retrieve the trusted base directory for plugins from an environment variable.
    #    If not configured, safe default is to prevent loading.
    trusted_plugin_base = os.environ.get("TRUSTED_PLUGIN_BASE_DIR")

    if not trusted_plugin_base:
        # If no trusted base is defined, it's insecure to proceed with an arbitrary path.
        # Return {"loaded": False} indicating failure to load due to security configuration.
        return {"loaded": False}

    # 2. Normalize both the trusted base path and the provided plugin_path to
    #    absolute paths. This helps prevent path traversal attacks (e.g., using '..')
    #    and ensures reliable comparison.
    absolute_trusted_base = os.path.abspath(trusted_plugin_base)
    absolute_plugin_path = os.path.abspath(plugin_path)

    # 3. Validate that the absolute_plugin_path is either the trusted base directory itself
    #    or a direct subdirectory of it.
    #    The 'os.sep' ensures that paths like '/app/plugins_malicious' do not match
    #    '/app/plugins' and are correctly identified as outside the trusted base.
    if not (absolute_plugin_path == absolute_trusted_base or
            absolute_plugin_path.startswith(absolute_trusted_base + os.sep)):
        # The provided plugin_path is outside the designated trusted directory structure.
        return {"loaded": False}

    # 4. Additionally, verify that the plugin_path actually exists and is a directory.
    #    This prevents adding non-existent paths or file paths to sys.path,
    #    which could lead to unexpected behavior or errors.
    if not os.path.isdir(absolute_plugin_path):
        return {"loaded": False}

    # Use the now validated and controlled absolute_plugin_path for insertion into sys.path.
    sys.path.insert(
        0,
        absolute_plugin_path,
    )
    # --- CWE-427 fix end ---

    module = None
    try:
        module = importlib.import_module(
            "graphql_plugin"
        )
    except ImportError:
        # If the module 'graphql_plugin' cannot be found within the search path
        # (including the validated plugin_path), module remains None.
        pass
    finally:
        # It's generally good practice to clean up sys.path if the entry is temporary
        # and not intended for global scope. However, for a simple CWE fix
        # and to avoid potential functional changes if subsequent imports depend
        # on it, we'll leave it as is, focusing solely on the path validation.
        pass

    return {
        "loaded": module is not None,
    }
