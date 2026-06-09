import logging

logger = logging.getLogger(
    "cloud"
)


def create_cloud_session(
    config: dict,
):
    logger.info(
        "cloud configuration=%r",
        config,
    )

    return create_session(
        access_key=config["access_key"],
        secret_key=config["secret_key"],
        session_token=config["session_token"],
    )
