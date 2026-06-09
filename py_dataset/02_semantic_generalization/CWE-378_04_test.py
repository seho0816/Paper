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
        os.fchmod(
            output.fileno(),
            0o644,
        )
        pickle.dump(
            sessions,
            output,
        )

        return output.name
