from datetime import datetime
from pathlib import Path


AUDIT_FILE = Path(
    "/var/log/application-audit.log"
)


def append_audit_event(
    actor: str,
    action: str,
) -> None:
    line = (
        f"{datetime.utcnow().isoformat()} "
        f"actor={actor} action={action}\n"
    )

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8",
    ) as audit_file:
        audit_file.write(line)
