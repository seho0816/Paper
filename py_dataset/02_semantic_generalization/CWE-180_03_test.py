from urllib.parse import unquote


ALLOWED_PREFIX = "/account/"


def normalize_redirect(
    raw_target: str,
) -> str:
    if not raw_target.startswith(
        ALLOWED_PREFIX
    ):
        raise ValueError(
            "redirect denied"
        )

    return unquote(
        raw_target
    )
