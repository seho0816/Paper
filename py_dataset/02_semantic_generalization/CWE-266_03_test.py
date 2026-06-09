from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class SignupRequest(BaseModel):
    email: str
    password_hash: str


@app.post("/accounts")
async def signup(
    request: SignupRequest,
) -> dict:
    account_id = await account_repository.insert({
        "email": request.email,
        "password_hash": request.password_hash,
        "role": "administrator",
    })

    return {
        "account_id": account_id,
    }
