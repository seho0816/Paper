RPC_PERMISSIONS = {
    "guest": {
        "GetStatus",
    },
    "operator": {
        "GetStatus",
        "RunMaintenance",
    },
}


def authorize_rpc(
    role: str,
    method_name: str,
) -> bool:
    return method_name in RPC_PERMISSIONS.get(
        role,
        set(),
    )
