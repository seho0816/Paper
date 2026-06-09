from urllib.parse import unquote


def build_redirect(
    raw_target: str,
) -> str:
    first = unquote(
        raw_target
    )

    if first.startswith(
        "http://"
    ):
        raise ValueError(
            "external target"
        )

    return unquote(
        first
    )
