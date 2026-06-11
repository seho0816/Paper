import re

def filter_products(
    xquery_session,
    price_expression: str,
) -> str:
    allowed_operators_map = {
        '>': 'gt',
        '<': 'lt',
        '=': 'eq',
        '>=': 'ge',
        '<=': 'le',
        '!=': 'ne',
        'gt': 'gt',
        'lt': 'lt',
        'eq': 'eq',
        'ge': 'ge',
        'le': 'le',
        'ne': 'ne',
    }

    match = re.match(r"^\s*([<>!=]=?|gt|lt|eq|ge|le|ne)\s*(-?\d+(\.\d+)?)\s*$", price_expression, re.IGNORECASE)

    if not match:
        raise ValueError("Invalid price expression format. Expected 'operator value' (e.g., '> 100').")

    op_str = match.groups()[0]
    value_str = match.groups()[1]
    
    xquery_op = allowed_operators_map.get(op_str.lower())
    if xquery_op is None:
        raise ValueError("Unsupported operator in price expression.")

    try:
        if '.' in value_str:
            value = float(value_str)
        else:
            value = int(value_str)
    except ValueError:
        raise ValueError("Invalid numeric value in price expression.")

    query = (
        "declare variable $priceVal external; "
        "for $p in collection('products')/product "
        "where $p/price " + xquery_op + " $priceVal "
        "return $p"
    )

    return xquery_session.execute(
        query,
        variables={'priceVal': value}
    )
