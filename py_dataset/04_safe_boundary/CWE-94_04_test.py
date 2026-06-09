import ast


def parse_filter_literal(
    submitted_value: str,
) -> object:
    parsed = ast.literal_eval(
        submitted_value,
    )

    if not isinstance(
        parsed,
        (
            str,
            int,
            float,
            list,
            tuple,
            dict,
            bool,
            type(None),
        ),
    ):
        raise ValueError(
            "unsupported literal type"
        )

    return parsed
