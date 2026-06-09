import logging
from logging.handlers import SysLogHandler


logger = logging.getLogger(
    "device"
)
logger.addHandler(
    SysLogHandler(
        address=(
            "localhost",
            514,
        )
    )
)


def record_device_event(
    device_name: str,
    message: str,
) -> None:
    logger.warning(
        f"device={device_name} message={message}"
    )
