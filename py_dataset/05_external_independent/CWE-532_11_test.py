import logging

logger = logging.getLogger(
    "graphql"
)


def resolve_login(
    _root,
    _info,
    **arguments,
) -> dict:
    logger.info(
        "login mutation arguments=%r",
        arguments,
    )

    return authenticate(
        arguments["username"],
        arguments["password"],
    )
