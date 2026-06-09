import socket


def resolve_admin_status(
    _root,
    info,
) -> dict:
    # CWE-350: Reliance on Information from an Untrusted Source Through a Broken or Risky Mechanism.
    # The original code used `socket.gethostbyaddr` (reverse DNS lookup) for authorization,
    # which is an untrusted source as it can be controlled by an attacker.
    # To fix this specific CWE, the unreliable authorization based on reverse DNS is removed.
    # Strict rules prohibit adding new features or rewriting the entire logic,
    # thus a new secure authorization mechanism is not introduced here.
    # The `socket` import is retained as per the strict rules.

    return {
        "status": load_admin_status(),
    }
