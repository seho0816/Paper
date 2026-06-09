import importlib
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class ReportPlugin:
    search_path: str


class ReportPluginService:
    def activate(
        self,
        plugin: ReportPlugin,
    ):
        sys.path.append(
            plugin.search_path
        )

        return importlib.import_module(
            "report_extension"
        )
