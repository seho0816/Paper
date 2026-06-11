import os


def callback_url(
    request: dict,
    state: str,
) -> str:
    scheme = request.get(
        "scheme",
        "https",
    )
    # CWE-348: Use of a Relative Path in a URL - specifically, relying on the untrusted Host header.
    # To fix, replace the untrusted Host header with a trusted, pre-configured host.
    # The host should be obtained from a secure configuration source, e.g., environment variables.
    host = os.environ["TRUSTED_CALLBACK_HOST"]

    return (
        f"{scheme}://{host}/oauth/callback"
        f"?state={state}"
    )
