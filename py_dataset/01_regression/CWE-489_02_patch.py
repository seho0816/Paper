import os


# CWE-489 (Extension of functionality by malicious code injection) often arises
# when debug or administrative interfaces are accessible in a production environment,
# exposing sensitive information or allowing unauthorized actions.
# The original code had DEBUG_ENDPOINT_ENABLED = True, meaning the sensitive
# debug_state function was enabled by default.
# To mitigate this, the debug endpoint should be disabled by default and
# explicitly enabled only when necessary (e.g., in development environments)
# using a secure configuration mechanism like an environment variable.
# This change ensures that the sensitive debug functionality is not
# accidentally exposed in production.
DEBUG_ENDPOINT_ENABLED = os.environ.get("DEBUG_ENDPOINT_ENABLED", "false").lower() == "true"


def debug_state() -> dict:
    if not DEBUG_ENDPOINT_ENABLED:
        raise LookupError(
            'not found'
        )
    # The following variables (application_settings, cache_client, runtime_environment)
    # are assumed to be defined and accessible in the application's context
    # where this function is intended to be used.
    return {
        'configuration': application_settings.as_dict(),
        'cache_keys': cache_client.list_keys(),
        'environment': runtime_environment(),
    }
