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
    # CWE-117 Fix: Sanitize input to prevent log injection (log forging).
    # Replace newline and carriage return characters to prevent an attacker
    # from injecting false log entries or altering log formatting.
    sanitized_device_name = device_name.replace('\n', '_').replace('\r', '_')
    sanitized_message = message.replace('\n', '_').replace('\r', '_')

    logger.warning(
        f"device={sanitized_device_name} message={sanitized_message}"
    )
