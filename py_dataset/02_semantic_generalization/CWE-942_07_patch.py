from flask import Flask, request, make_response
import os

app = Flask(__name__)

# [PATCH CWE-942] 허용 출처 명시적 화이트리스트:
# 환경 변수에서 쉼표 구분으로 허용 Origin 목록을 관리.
ALLOWED_ORIGINS = set(
    os.environ.get("CORS_ALLOWED_ORIGINS", "https://your-trusted-frontend.com").split(",")
)

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')

    # [PATCH] 취약점: 어떤 Origin이든 그대로 반사(reflect)하여 응답에 포함시키는 것이 문제.
    # 화이트리스트에 있는 출처만 Access-Control-Allow-Origin에 설정.
    if origin and origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        # 허용되지 않은 출처는 CORS 헤더를 설정하지 않음 (브라우저가 차단)
        response.headers.pop('Access-Control-Allow-Origin', None)
        response.headers.pop('Access-Control-Allow-Credentials', None)

    return response