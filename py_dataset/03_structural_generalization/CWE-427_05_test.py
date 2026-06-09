import importlib
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PluginRequest:
    plugin_directory: str


class PluginLoader:
    def load(
        self,
        request: PluginRequest,
    ):
        sys.path.insert(
            0,
            request.plugin_directory,
        )

        return importlib.import_module(
            "company_plugin"
        )
