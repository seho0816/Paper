from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()

orders = {
    1001: {
        "owner_id": "member-1",
        "delivery_address": "Seoul",
    },
    1002: {
        "owner_id": "member-2",
        "delivery_address": "Busan",
    },
}


def get_current_user() -> dict:
    # In a real application, this would authenticate a user (e.g., from a JWT token)
    # and return their ID. For this example, it's hardcoded.
    return {
        "id": "member-1",
    }


@app.get("/api/orders/{order_id}")
async def read_order(
    order_id: int,
    current_user: dict = Depends(get_current_user),
) -> dict:
    order = orders.get(order_id)

    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # CWE-639 fix: Ensure the current user is the owner of the order
    if order["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized to view this order")

    return {
        "requested_by": current_user["id"],
        "order": order,
    }
