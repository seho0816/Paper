from flask import request


def grant_permission():
    actor = load_user_from_session(
        request.cookies["session_id"]
    )
    target_id = str(
        request.json["target_id"]
    )
    permission = str(
        request.json["permission"]
    )

    grant_user_permission(
        target_id,
        permission,
    )

    return {
        "granted_by": actor["id"],
    }
