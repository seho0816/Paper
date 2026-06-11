from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


# account_repository는 예시로 가정된 객체입니다.
# 실제 환경에서는 데이터베이스 연동 및 계정 관리를 위한 적절한 구현이 필요합니다.
class AccountRepository:
    async def insert(self, account_data: dict) -> int:
        # 실제 데이터베이스 삽입 로직을 여기에 구현
        # 이 예시에서는 단순히 가상의 ID를 반환합니다.
        print(f"Inserting account: {account_data}")
        return 12345 # 가상의 account_id

account_repository = AccountRepository()


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
        "role": "user", # CWE-266 취약점: 기본 역할 'administrator'에서 'user'로 변경하여 권한 상승 방지
    })

    return {
        "account_id": account_id,
    }
