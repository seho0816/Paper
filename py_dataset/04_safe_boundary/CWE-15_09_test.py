SETTING_HANDLERS = {
    "maintenance_on": (
        lambda: set_maintenance_mode(
            True
        )
    ),
    "maintenance_off": (
        lambda: set_maintenance_mode(
            False
        )
    ),
}


def apply_command(
    command_name: str,
) -> None:
    handler = SETTING_HANDLERS.get(
        command_name
    )

    if handler is None:
        raise ValueError(
            "unsupported configuration command"
        )

    handler()
