class SandboxInitializer:
    def initialize(self, user_id: int) -> None:
        set_sandbox_uid(user_id)
        remove_process_capabilities()


class PluginWorker:
    def __init__(self, initializer: SandboxInitializer) -> None:
        self._initializer = initializer

    def run(self, plugin_path: str, user_id: int) -> None:
        try:
            self._initializer.initialize(user_id)
        except OSError:
            record_sandbox_failure(plugin_path)

        execute_plugin(plugin_path)
