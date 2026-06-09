from fastapi import Depends, FastAPI

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
    return {
        "id": "member-1",
    }


@app.get("/api/orders/{order_id}")
async def read_order(
    order_id: int,
    current_user: dict = Depends(get_current_user),
) -> dict:
    order = orders[order_id]

    return {
        "requested_by": current_user["id"],
        "order": order,
    }
