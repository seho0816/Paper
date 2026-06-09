DEBUG = False
ALLOW_GUEST = False


def update_runtime_flags(
    submitted: dict,
) -> None:
    globals().update(
        submitted
    )
