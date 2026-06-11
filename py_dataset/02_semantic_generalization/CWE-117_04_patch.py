from datetime import datetime
from pathlib import Path


AUDIT_FILE = Path(
    "/var/log/application-audit.log"
)


def append_audit_event(
    actor: str,
    action: str,
) -> None:
    # CWE-117 fix: Neutralize newline characters in actor and action
    # to prevent log forging by ensuring they do not break log lines.
    sanitized_actor = actor.replace('\n', '_').replace('\r', '_')
    sanitized_action = action.replace('\n', '_').replace('\r', '_')

    line = (
        f"{datetime.utcnow().isoformat()} "
        f"actor={sanitized_actor} action={sanitized_action}\n"
    )

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8",
    ) as audit_file:
        audit_file.write(line)
