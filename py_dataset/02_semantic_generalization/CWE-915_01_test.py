from dataclasses import dataclass

from fastapi import FastAPI

app = FastAPI()


@dataclass
class MemberAccount:
    nickname: str
    email: str
    role: str = "member"
    reward_balance: int = 0


account = MemberAccount(
    nickname="new-member",
    email="member@example.com",
)


@app.patch("/api/member/profile")
async def update_member_profile(
    payload: dict,
) -> dict:
    for field_name, field_value in payload.items():
        setattr(
            account,
            field_name,
            field_value,
        )

    return account.__dict__
