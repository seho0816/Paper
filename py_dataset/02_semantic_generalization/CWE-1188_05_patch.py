from dataclasses import dataclass

@dataclass
class PluginSettings:
    sandbox_enabled: bool = True  # Default to sandbox enabled for security
    filesystem_read_only: bool = True  # Default to read-only filesystem for security

def launch_plugin(plugin_path: str, settings: PluginSettings = PluginSettings()):
    return plugin_runtime.launch(
        plugin_path,
        sandbox=settings.sandbox_enabled,
        read_only=settings.filesystem_read_only,
    )
