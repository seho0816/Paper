from array import array


def selected_price(
    prices: array,
    index_value: str,
) -> float:
    index = int(
        index_value
    )

    return float(
        prices[index]
    )
