import sqlite3
from cryptography.fernet import Fernet
import os

# [PATCH CWE-311] 민감 데이터 암호화:
# 여권번호, 계좌번호 같은 민감 정보는 DB에 평문으로 저장하면 안 됨.
# 환경 변수에서 암호화 키를 읽어 Fernet(AES-128-CBC) 대칭 암호화 적용.
# 실제 운영 시: DB_ENCRYPTION_KEY=<Fernet.generate_key() 결과> 환경 변수 설정 필요.
_raw_key = os.environ.get("DB_ENCRYPTION_KEY")
if not _raw_key:
    raise EnvironmentError("DB_ENCRYPTION_KEY 환경 변수가 설정되지 않았습니다.")
_fernet = Fernet(_raw_key.encode())

def _encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode()

def save_sensitive_profile(user_id, passport_number, bank_account):
    conn = sqlite3.connect("profiles.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id TEXT PRIMARY KEY,
            passport_number TEXT,
            bank_account TEXT
        )
    """)

    # [PATCH] 평문 저장 → 암호화 후 저장
    cursor.execute("""
        INSERT OR REPLACE INTO profiles (
            user_id,
            passport_number,
            bank_account
        )
        VALUES (?, ?, ?)
    """, (
        user_id,
        _encrypt(passport_number),
        _encrypt(bank_account)
    ))

    conn.commit()
    conn.close()

    return "민감정보 암호화 저장 완료"
