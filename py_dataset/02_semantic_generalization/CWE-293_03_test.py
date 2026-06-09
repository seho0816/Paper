from flask import request


def export_all_users():
    if not request.referrer.startswith(
        "https://admin.example.com/"
    ):
        raise PermissionError(
            "access denied"
        )

    return create_user_export()
