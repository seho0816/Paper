from dataclasses import dataclass

@dataclass
class PluginSettings:
    sandbox_enabled: bool = False
    filesystem_read_only: bool = False

def launch_plugin(plugin_path: str, settings: PluginSettings = PluginSettings()):
    return plugin_runtime.launch(
        plugin_path,
        sandbox=settings.sandbox_enabled,
        read_only=settings.filesystem_read_only,
    )
