import os
import pickle
import tempfile


def dump_sessions(
    sessions: list[dict],
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="wb",
        delete=False,
    ) as output:
        # CWE-378: Insecure Creation of Temporary File With Insecure Permissions
        # The explicit os.fchmod to 0o644 sets insecure permissions.
        # tempfile.NamedTemporaryFile by default creates files with secure permissions (e.g., 0o600).
        # Removing the os.fchmod call ensures the default secure permissions are used.
        pickle.dump(
            sessions,
            output,
        )

        return output.name
