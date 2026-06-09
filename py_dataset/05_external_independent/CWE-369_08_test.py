def resolve_ratio(
    _root,
    _info,
    numerator: float,
    denominator: float,
) -> dict:
    return {
        "ratio": (
            numerator
            / denominator
        ),
    }
