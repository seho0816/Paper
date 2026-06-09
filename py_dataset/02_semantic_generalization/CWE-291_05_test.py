from flask import request


ADMIN_NETWORKS = {
    "127.0.0.1",
    "10.20.30.40",
}


def admin_dashboard():
    if request.remote_addr not in ADMIN_NETWORKS:
        raise PermissionError(
            "access denied"
        )

    return load_admin_dashboard()
