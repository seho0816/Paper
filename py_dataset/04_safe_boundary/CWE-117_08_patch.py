import json
from pathlib import Path


AUDIT_FILE = Path(
    "/var/log/audit.jsonl"
)


def write_audit_event(
    actor: str,
    action: str,
) -> None:
    event = {
        "actor": actor,
        "action": action,
    }
    serialized = json.dumps(
        event,
        ensure_ascii=True,
        separators=(",", ":"),
    )

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8",
    ) as output:
        output.write(
            serialized + "\n"
        )

