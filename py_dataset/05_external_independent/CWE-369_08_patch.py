def resolve_ratio(
    _root,
    _info,
    numerator: float,
    denominator: float,
) -> dict:
    if denominator == 0.0:
        # CWE-369: Division by Zero.
        # Handle the case where the denominator is zero to prevent
        # ZeroDivisionError (for integers) or problematic float results
        # like 'inf' or 'nan' which can lead to undesirable behavior
        # in downstream applications. Returning 0.0 is a common and safe
        # default when a finite ratio is expected.
        ratio_value = 0.0
    else:
        ratio_value = numerator / denominator
    return {
        "ratio": ratio_value,
    }
