import logging

logger = logging.getLogger(
    "graphql"
)


def resolve_login(
    _root,
    _info,
    **arguments,
) -> dict:
    # CWE-532: Inclusion of Sensitive Information in Log Files
    # Create a copy of the arguments for logging to prevent sensitive data (like 'password')
    # from being written to log files.
    sanitized_arguments = arguments.copy()
    if "password" in sanitized_arguments:
        # Remove the 'password' field entirely from the logging arguments.
        # Alternatively, it could be masked as '[REDACTED]' if its presence is necessary to indicate.
        del sanitized_arguments["password"]

    logger.info(
        "login mutation arguments=%r",
        sanitized_arguments,  # Log the sanitized version
    )

    return authenticate(
        arguments["username"],
        arguments["password"],
    )
