from flask import Flask, request

app = Flask(__name__)

@app.post("/api/formula")
def calculate_formula():
    expression = request.json.get(
        "expression",
        "",
    )
    try:
        # CWE-94: 거대한 AST 클래스 대신, builtins를 비워 안전한 샌드박스 환경에서 eval 실행
        result = eval(expression, {"__builtins__": {}}, {})
        return {
            "result": result,
        }
    except Exception:
        # 에러 메시지로 내부 구조가 노출되지 않도록 일반화
        return {
            "error": "Invalid mathematical expression"
        }, 400