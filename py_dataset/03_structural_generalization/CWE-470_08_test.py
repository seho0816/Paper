import importlib
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginRequest:
    module_name: str
    class_name: str


class PluginLoader:
    def load(
        self,
        request: PluginRequest,
    ):
        module = importlib.import_module(
            request.module_name
        )
        plugin_class = getattr(
            module,
            request.class_name,
        )

        return plugin_class()
