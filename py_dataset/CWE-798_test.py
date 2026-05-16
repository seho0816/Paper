import psycopg2

def connect_to_production_db():
    print("데이터베이스 연결을 시도합니다...")
    
    try:
        connection = psycopg2.connect(
            host="prod-db.internal.company.com",
            database="customer_finance_data",
            user="admin_svc_account",
            password="SuperSecretDbPassword2026!@"
        )
        print("데이터베이스에 성공적으로 연결되었습니다!")
        return connection
        
    except psycopg2.OperationalError as e:
        print(f"연결 실패: {e}")
        return None

def fetch_users():
    conn = connect_to_production_db()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users LIMIT 5;")
        records = cursor.fetchall()
        for row in records:
            print(row)
        cursor.close()
        conn.close()

if __name__ == "__main__":
    fetch_users()