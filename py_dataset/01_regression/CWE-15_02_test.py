import os


def apply_environment(
    payload: dict,
) -> None:
    for name, value in payload.items():
        os.environ[
            str(name)
        ] = str(value)
