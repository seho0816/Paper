from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class CheckoutPayload(BaseModel):
    product_id: str
    unit_price: int
    quantity: int

@router.post("/orders/preview")
def order_total(payload: CheckoutPayload) -> dict:
    total = payload.unit_price * payload.quantity
    return {"product_id": payload.product_id, "total": total}
