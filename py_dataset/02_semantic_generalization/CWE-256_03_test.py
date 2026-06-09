from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


class SignupRequest(BaseModel):
    email: str
    password: str


@app.post("/accounts")
async def create_account(
    request: SignupRequest,
) -> dict:
    account_id = await account_repository.insert({
        "email": request.email,
        "password": request.password,
    })

    return {
        "account_id": account_id,
    }
