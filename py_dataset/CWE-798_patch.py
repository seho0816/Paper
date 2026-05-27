import psycopg2
import os

def connect_to_production_db():
    print("데이터베이스 연결을 시도합니다...")

    # [PATCH CWE-798] 하드코딩된 자격증명 제거:
    # 소스코드에 비밀번호를 직접 작성하면 Git 히스토리 등을 통해 영구 노출됨.
    # 환경 변수(os.environ)에서 읽어오도록 변경.
    # 실행 전 환경 변수 설정 필요:
    #   export DB_HOST=prod-db.internal.company.com
    #   export DB_NAME=customer_finance_data
    #   export DB_USER=admin_svc_account
    #   export DB_PASSWORD=<실제_비밀번호>
    db_host = os.environ.get("DB_HOST")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")

    if not all([db_host, db_name, db_user, db_password]):
        print("오류: DB 접속 정보 환경 변수가 설정되지 않았습니다.")
        return None

    try:
        connection = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
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