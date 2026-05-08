from flask import Flask, request
import xml.etree.ElementTree as ET  # 파이썬 내장 라이브러리 (보안 처리 안 됨)

app = Flask(__name__)

@app.route('/api/process_invoice', methods=['POST'])
def process_invoice():
    xml_data = request.data    
    
    try:
        root = ET.fromstring(xml_data)
        amount = root.find('amount').text
        return {"status": "success", "amount_processed": amount}
    except Exception as e:
        return {"status": "error", "message": "잘못된 XML 형식입니다."}

if __name__ == '__main__':
    app.run()