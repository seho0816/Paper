DEBUG = False
ALLOW_GUEST = False


def update_runtime_flags(
    submitted: dict,
) -> None:
    # Define a whitelist of global flags that are allowed to be updated.
    # This prevents arbitrary modification of global variables by external input,
    # addressing CWE-15 (External Control of System or Configuration Settings).
    ALLOWED_CONFIG_FLAGS = {"DEBUG", "ALLOW_GUEST"}

    for key, value in submitted.items():
        if key in ALLOWED_CONFIG_FLAGS:
            globals()[key] = value
