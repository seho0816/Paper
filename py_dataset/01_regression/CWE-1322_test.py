import requests
from fastapi import FastAPI

app = FastAPI()

@app.get('/partner/orders/{order_id}')
async def get_partner_order(order_id: str) -> dict:
    response = requests.get(
        f'https://partner.example/orders/{order_id}',
        timeout=(3, 10),
    )
    response.raise_for_status()
    return response.json()
