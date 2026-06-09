import pandas as pd


def enrich_orders(
    orders: pd.DataFrame,
    customers: pd.DataFrame,
) -> list[dict]:
    enriched = []

    for _, order in orders.iterrows():
        matched = customers[
            customers[
                "customer_id"
            ]
            == order[
                "customer_id"
            ]
        ]
        enriched.append({
            "order_id": order[
                "order_id"
            ],
            "customer_name": matched.iloc[
                0
            ][
                "name"
            ],
        })

    return enriched
