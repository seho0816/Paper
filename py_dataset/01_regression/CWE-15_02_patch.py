import os

# Define a whitelist of allowed environment variable names.
# This list must be carefully curated based on the application's specific needs.
# Critical system variables (e.g., PATH, LD_PRELOAD, SHELL) or sensitive credentials
# should NEVER be included in this whitelist.
ALLOWED_ENV_VARS = {
    "APP_SETTING_DEBUG_MODE",
    "APP_SETTING_LOG_LEVEL",
    "APP_SETTING_FEATURE_FLAG_A",
    "APP_SETTING_FEATURE_FLAG_B",
}


def apply_environment(
    payload: dict,
) -> None:
    for name, value in payload.items():
        # Convert the potential environment variable name to string.
        str_name = str(name)
        # Only set environment variables if their name is explicitly in the whitelist.
        # This prevents external control over arbitrary system or configuration settings (CWE-15).
        if str_name in ALLOWED_ENV_VARS:
            os.environ[
                str_name
            ] = str(value)
