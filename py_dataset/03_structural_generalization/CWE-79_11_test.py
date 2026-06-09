from dataclasses import dataclass


@dataclass(frozen=True)
class AuditEntry:
    actor: str
    detail: str


class AuditRepository:
    def find_recent(self) -> list[AuditEntry]:
        return [
            AuditEntry(
                actor="external-user",
                detail="<img src=x onerror=alert(1)>",
            )
        ]


class AuditDashboard:
    def __init__(self, repository: AuditRepository) -> None:
        self._repository = repository

    def render(self) -> str:
        rows = ""
        for entry in self._repository.find_recent():
            rows += (
                "<tr>"
                f"<td>{entry.actor}</td>"
                f"<td>{entry.detail}</td>"
                "</tr>"
            )
        return "<table>" + rows + "</table>"
