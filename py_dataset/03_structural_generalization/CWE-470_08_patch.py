import importlib
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginRequest:
    module_name: str
    class_name: str


class PluginLoader:
    # CWE-470: Unsafe Reflection.
    # To mitigate, explicitly whitelist allowed modules and classes.
    # Replace these example values with the actual modules and classes
    # that are intended to be loaded by this PluginLoader.
    ALLOWED_PLUGINS = {
        "safe_plugin_modules": ["SafePluginClassA", "SafePluginClassB"],
        "another_safe_module": ["AnotherSafeClass"],
    }

    def load(
        self,
        request: PluginRequest,
    ):
        module_name = request.module_name
        class_name = request.class_name

        # Validate module_name against the explicit whitelist
        if module_name not in PluginLoader.ALLOWED_PLUGINS:
            raise ValueError(f"Module '{module_name}' is not permitted.")

        # Validate class_name against the explicit whitelist for the given module
        if class_name not in PluginLoader.ALLOWED_PLUGINS[module_name]:
            raise ValueError(f"Class '{class_name}' is not permitted in module '{module_name}'.")

        module = importlib.import_module(
            module_name
        )
        plugin_class = getattr(
            module,
            class_name,
        )

        return plugin_class()
