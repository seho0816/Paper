class SandboxInitializer:
    def initialize(self, user_id: int) -> None:
        # CWE-273: External Control of Assumed-Immutable Resources
        # The 'user_id' parameter, if controlled by an external entity, could allow
        # an attacker to set the sandbox UID to a privileged user (e.g., root)
        # or an arbitrary user, potentially bypassing the intended security isolation.
        # The security context (UID) of a sandbox should be an internally determined
        # and assumed-immutable resource, not subject to external influence for critical operations.

        # Fix: Use a predefined, safe, unprivileged UID for the sandbox,
        # ensuring that the sandbox always operates with a fixed, secure privilege level,
        # regardless of the 'user_id' provided by external input.
        # 65534 is a common UID for the 'nobody' user on many Linux systems, serving as
        # a suitable generic unprivileged user for sandboxing purposes.
        SAFE_SANDBOX_UID = 65534
        set_sandbox_uid(SAFE_SANDBOX_UID)
        remove_process_capabilities()


class PluginWorker:
    def __init__(self, initializer: SandboxInitializer) -> None:
        self._initializer = initializer

    def run(self, plugin_path: str, user_id: int) -> None:
        try:
            # The 'user_id' parameter is still passed to initialize to maintain the signature,
            # but the SandboxInitializer now safely ignores it for the security-critical UID setting.
            self._initializer.initialize(user_id)
        except OSError:
            record_sandbox_failure(plugin_path)

        execute_plugin(plugin_path)
