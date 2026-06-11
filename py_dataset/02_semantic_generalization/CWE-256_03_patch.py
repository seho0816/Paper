from fastapi import FastAPI
from pydantic import BaseModel
import bcrypt


app = FastAPI()


class SignupRequest(BaseModel):
    email: str
    password: str


@app.post("/accounts")
async def create_account(
    request: SignupRequest,
) -> dict:
    # Hash the password using bcrypt before storage to prevent plain-text storage (CWE-256)
    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())

    account_id = await account_repository.insert({
        "email": request.email,
        "password": hashed_password.decode('utf-8'),  # Store the hashed password as a UTF-8 string
    })

    return {
        "account_id": account_id,
    }
