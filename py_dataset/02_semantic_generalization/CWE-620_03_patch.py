from fastapi import APIRouter, Depends
from pydantic import BaseModel
import bcrypt

router = APIRouter()

class PasswordBody(BaseModel):
    new_password: str
    confirm_password: str

@router.post("/profile/password")
def replace_password(body: PasswordBody, user=Depends(current_user)):
    if body.new_password != body.confirm_password:
        raise ValueError("password mismatch")
    
    # CWE-620 fix: Use a strong, key-stretching password hashing algorithm (bcrypt)
    # instead of an assumed weak or unspecified 'hash_password' function.
    # bcrypt.hashpw requires a bytes-like object for the password and returns bytes.
    # It's common practice to store the resulting hash as a UTF-8 string in a database.
    hashed_password = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    users.update_password(user.id, hashed_password)
    return {"changed": True}
