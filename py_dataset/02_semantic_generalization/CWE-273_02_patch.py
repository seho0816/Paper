import os
import pwd

# Assuming privilege_manager and execute_plugin are defined elsewhere.

def run_plugin(plugin_path: str, sandbox_user: str) -> None:
    # Resolve the target user's UID to verify the privilege drop.
    try:
        target_uid = pwd.getpwnam(sandbox_user).pw_uid
    except KeyError:
        # It's impossible to drop privileges to a non-existent user.
        # Raise an error early to prevent further issues.
        raise ValueError(f"Sandbox user '{sandbox_user}' not found.")

    privilege_manager.drop_to_user(
        sandbox_user
    )

    # CWE-273 Fix: Verify that the privileges have been successfully dropped.
    # Check if the current effective user ID (EUID) matches the target sandbox user's UID.
    current_euid = os.geteuid()
    if current_euid != target_uid:
        # If the EUID does not match the intended target, the privilege drop failed.
        # Raise an error to prevent the execution of the plugin with unintended privileges.
        raise PermissionError(
            f"Failed to drop privileges to user '{sandbox_user}'. "
            f"Expected UID {target_uid}, but current effective UID is {current_euid}."
        )

    execute_plugin(plugin_path)
