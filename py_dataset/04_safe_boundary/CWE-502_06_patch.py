import json
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionState:
    user_id: str
    selected_tab: str


def restore_session(
    serialized_state: str,
) -> SessionState:
    try:
        parsed = json.loads(
            serialized_state,
        )
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON format for session state") from e

    if not isinstance(parsed, dict):
        raise ValueError(
            "session state must be an object"
        )

    user_id = parsed.get(
        "user_id",
    )
    selected_tab = parsed.get(
        "selected_tab",
    )

    if not isinstance(user_id, str):
        raise ValueError(
            "invalid user_id"
        )

    if not isinstance(selected_tab, str):
        raise ValueError(
            "invalid selected_tab"
        )

    return SessionState(
        user_id=user_id,
        selected_tab=selected_tab,
    )
