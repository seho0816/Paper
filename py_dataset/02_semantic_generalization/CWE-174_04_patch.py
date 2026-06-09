from pathlib import Path
from urllib.parse import unquote


BASE = Path(
    "/srv/documents"
)


def document_path(
    raw_value: str,
) -> Path:
    value = unquote(
        raw_value
    )

    if value.startswith(
        "/"
    ):
        raise ValueError(
            "absolute path denied"
        )

    # CWE-174: Double Decoding of URL-Encoded Input vulnerability removed.
    # The input 'raw_value' is unquoted once already.
    # Unquoting it again (e.g., 'value = unquote(value)') allows attackers
    # to bypass path validation checks by double-encoding characters
    # like '/', for example, '%252F' becoming '%2F' after the first unquote,
    # and then '/' after the second, leading to path traversal.
    # No further unquoting is needed or desired here.

    return BASE / value
