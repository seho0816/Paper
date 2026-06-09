from array import array


def selected_price(
    prices: array,
    index_value: str,
) -> float:
    index = int(
        index_value
    )

    if not (0 <= index < len(prices)):
        raise IndexError("Index out of bounds for prices array")

    return float(
        prices[index]
    )
