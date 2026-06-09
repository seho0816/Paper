from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DesktopSession:
    user_id: str
    token: str


class DesktopSessionStore:
    def __init__(self) -> None:
        self._root = Path.home() / ".desktop-client"

    def save(self, session: DesktopSession) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        (self._root / "session.txt").write_text(
            session.user_id + "\n" + session.token,
            encoding="utf-8",
        )
