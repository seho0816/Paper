import pandas as pd


def enrich_orders(
    orders: pd.DataFrame,
    customers: pd.DataFrame,
) -> list[dict]:
    # CWE-407: The original code iterated through each order and performed a linear scan
    # on the customers DataFrame for each order, leading to O(N*M) complexity.
    # This patch replaces the inefficient loop with a single pandas merge operation,
    # which leverages optimized C implementations (e.g., hash joins) resulting in
    # significantly better performance (typically O(N+M) or O(N log M)).

    # Perform a left merge to combine 'orders' with 'customers' based on 'customer_id'.
    # A left merge ensures all orders are retained. If a customer_id in 'orders'
    # does not have a match in 'customers', the customer-related columns will be NaN.
    merged_df = orders.merge(customers, on="customer_id", how="left")

    # Select the required columns ('order_id' and 'name') and rename 'name' to 'customer_name'
    # to match the structure of the original output.
    result_df = merged_df[[
        "order_id",
        "name"
    ]].rename(columns={"name": "customer_name"})

    # Convert the resulting DataFrame to a list of dictionaries, as per the function's return type.
    return result_df.to_dict(orient="records")
