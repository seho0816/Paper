import logging


logger = logging.getLogger(
    "application"
)


def write_custom_log(
    message_template: str,
    values: tuple,
) -> None:
    logger.info(
        message_template
        % values
    )
