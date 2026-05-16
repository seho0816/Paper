from flask import Flask, request
import json
import re

app = Flask(__name__)

def sanitize_log(value: str) -> str:
    """
    [PATCH CWE-117] 로그 삽입(Log Injection) 방지:
    개행 문자(\n, \r)와 탭(\t)을 제거하여 공격자가 로그를 위조하지 못하도록 함.
    """
    if value is None:
        return "NONE"
    return re.sub(r'[\n\r\t]', '_', str(value))

@app.route('/process-payment', methods=['POST'])
def process():
    CCNumber = request.form.get('cc')
    expDate = request.form.get('expDate')
    CVV = request.form.get('CVV')
    orderNumber = request.form.get('orderNumber')
    success = processPayment(CCNumber, expDate, CVV, orderNumber)

    # [PATCH CWE-532] 민감 정보(신용카드 번호, CVV, 유효기간) 로그 기록 금지.
    # 주문번호와 결과(성공/실패)만 sanitize하여 기록.
    safe_order = sanitize_log(orderNumber)
    safe_result = sanitize_log(success)

    with open('log.txt', 'a') as log_file:
        log_file.write("PAYMENT " + safe_order + " " + safe_result + "\n")

app.run(host="0.0.0.0")