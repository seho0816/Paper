POLICY = {
    "readonly": {
        "document.view",
    },
    "security_admin": {
        "document.view",
        "secret.rotate",
    },
}


def is_allowed(
    role: str,
    action: str,
) -> bool:
    return action in POLICY.get(
        role,
        set(),
    )
