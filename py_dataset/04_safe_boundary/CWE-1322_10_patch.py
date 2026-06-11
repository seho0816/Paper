import httpx
from fastapi import FastAPI

app = FastAPI()

@app.get('/partner/orders/{order_id}')
async def get_partner_order(order_id: str) -> dict:
    timeout = httpx.Timeout(
        connect=3.0,
        read=10.0,
        write=5.0,
        pool=3.0,
    )
    async with httpx.AsyncClient(
        timeout=timeout
    ) as client:
        response = await client.get(
            f'https://partner.example/orders/{order_id}'
        )
        response.raise_for_status()
        return response.json()

