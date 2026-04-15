import os
from google import genai
from dotenv import load_dotenv

# --- API 키 안전하게 불러오기 (.env 사용) ---
load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("⚠️ 오류: .env 파일에 'GEMINI_API_KEY'가 없습니다!")
    exit()

# --- 구글 제미나이 최신 문법 적용 ---
client = genai.Client(api_key=api_key)

def login_user(username, password):
    query = f"SELECT * FROM users WHERE id = '{username}' AND pw = '{password}'"
    print(f"Executing: {query}")
    return query

def calculate_data(a, b):
    return a + b

print("Hello World")