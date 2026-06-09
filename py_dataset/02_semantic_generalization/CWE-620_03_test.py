from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()

class PasswordBody(BaseModel):
    new_password: str
    confirm_password: str

@router.post("/profile/password")
def replace_password(body: PasswordBody, user=Depends(current_user)):
    if body.new_password != body.confirm_password:
        raise ValueError("password mismatch")
    users.update_password(user.id, hash_password(body.new_password))
    return {"changed": True}
