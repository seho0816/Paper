from enum import Enum


class Operation(str, Enum):
    STATUS = "status"
    EXPORT = "export"


HANDLERS = {
    Operation.STATUS: get_status,
    Operation.EXPORT: export_records,
}


def dispatch_operation(
    operation_name: str,
):
    try:
        operation = Operation(
            operation_name
        )
    except ValueError as error:
        raise ValueError(
            "unsupported operation"
        ) from error

    return HANDLERS[
        operation
    ]()

