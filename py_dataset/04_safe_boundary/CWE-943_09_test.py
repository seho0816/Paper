def reject_operator_keys(
    value,
) -> None:
    if isinstance(
        value,
        dict,
    ):
        for key, item in value.items():
            if str(key).startswith(
                "$"
            ):
                raise ValueError(
                    "query operators are not allowed"
                )

            reject_operator_keys(
                item
            )

    if isinstance(
        value,
        list,
    ):
        for item in value:
            reject_operator_keys(
                item
            )
