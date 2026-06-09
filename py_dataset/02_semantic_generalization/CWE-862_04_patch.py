from flask import request, abort


def grant_permission():
    actor = load_user_from_session(
        request.cookies["session_id"]
    )

    # CWE-862 fix: Add authorization check
    # 1. Ensure a user is authenticated. If no actor is loaded, the user is unauthenticated.
    if actor is None:
        abort(401)  # Unauthorized: User is not authenticated or session is invalid.

    # 2. Check if the authenticated user has the necessary authority (authorization)
    #    to grant permissions. This example assumes the actor object has an 'is_admin'
    #    flag. In a real-world scenario, this would be based on roles, groups, or more
    #    granular permission checks (e.g., actor.has_permission("grant_permission")).
    if not actor.get("is_admin", False):
        abort(403)  # Forbidden: User is authenticated but does not have the authority to perform this action.

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
