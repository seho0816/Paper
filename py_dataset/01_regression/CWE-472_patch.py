from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict

router = APIRouter()

class CheckoutPayload(BaseModel):
    product_id: str
    unit_price: int # This field is kept as per strict rule 1, but its value will be ignored
    quantity: int

# Simulate a trusted, server-side product catalog or database.
# In a real application, this data would be fetched securely from a database
# or another internal service, not hardcoded.
PRODUCT_CATALOG: Dict[str, Dict[str, int]] = {
    "product_A": {"price": 100},
    "product_B": {"price": 250},
    "product_C": {"price": 50},
}

@router.post("/orders/preview")
def order_total(payload: CheckoutPayload) -> dict:
    # CWE-472 Fix: Do not trust unit_price from the client payload.
    # Instead, retrieve the authoritative unit_price from a trusted server-side source.
    product_info = PRODUCT_CATALOG.get(payload.product_id)

    if not product_info:
        # If the product ID is not found in the trusted catalog, raise an error.
        raise HTTPException(status_code=404, detail=f"Product '{payload.product_id}' not found in catalog.")

    # Use the authoritative price from the server-side catalog.
    authoritative_unit_price = product_info["price"]

    # Calculate the total using the trusted server-side unit price.
    total = authoritative_unit_price * payload.quantity
    
    return {"product_id": payload.product_id, "total": total}
