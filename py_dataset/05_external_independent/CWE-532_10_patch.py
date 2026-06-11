import logging

logger = logging.getLogger(
    "cloud"
)


def create_cloud_session(
    config: dict,
):
    loggable_config = config.copy()
    sensitive_keys = ["access_key", "secret_key", "session_token"]
    for key in sensitive_keys:
        if key in loggable_config:
            loggable_config[key] = "[REDACTED]"

    logger.info(
        "cloud configuration=%r",
        loggable_config,
    )

    return create_session(
        access_key=config["access_key"],
        secret_key=config["secret_key"],
        session_token=config["session_token"],
    )
