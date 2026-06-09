from flask import request


def reset_administrator_password():
    new_password = str(
        request.json["new_password"]
    )
    update_administrator_password(
        new_password,
    )

    return {
        "updated": True,
    }
