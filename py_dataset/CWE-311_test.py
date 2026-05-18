import sqlite3

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

    cursor.execute("""
        INSERT OR REPLACE INTO profiles (
            user_id,
            passport_number,
            bank_account
        )
        VALUES (?, ?, ?)
    """, (
        user_id,
        passport_number,
        bank_account
    ))

    conn.commit()
    conn.close()

    return "민감정보 저장 완료"