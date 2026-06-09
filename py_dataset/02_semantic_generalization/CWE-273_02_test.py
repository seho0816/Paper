def run_plugin(plugin_path: str, sandbox_user: str) -> None:
    privilege_manager.drop_to_user(
        sandbox_user
    )
    execute_plugin(plugin_path)
