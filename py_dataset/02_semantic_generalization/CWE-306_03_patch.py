import os
import jwt
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.environ.get("SECRET_KEY", "default_secret")
ALGORITHM = "HS256"

class User(BaseModel):
    username: str
    is_admin: bool = False

def generate_user_export():
    yield "id,username,email,status\n"
    yield "1,admin_user,admin@example.com,active\n"

app = FastAPI()
security = HTTPBearer()

async def get_current_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("is_admin"):
            raise HTTPException(status_code=403, detail="Forbidden")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Unauthorized")

# CWE-306: 함수의 인자를 변경하지 않고, dependencies 속성을 사용하여 구조를 완벽하게 보존
@app.get("/api/admin/users/export", dependencies=[Depends(get_current_admin_user)])
async def export_users():
    export_stream = generate_user_export()
    return StreamingResponse(
        export_stream,
        media_type="text/csv",
    )