from flask import Flask, request
import defusedxml.ElementTree as ET  # [PATCH CWE-611] XXE 안전 라이브러리로 교체

app = Flask(__name__)

@app.route('/api/process_invoice', methods=['POST'])
def process_invoice():
    xml_data = request.data

    try:
        # [PATCH CWE-611] XML External Entity (XXE) 주입 방지:
        # 파이썬 내장 xml.etree.ElementTree는 외부 엔티티를 자동으로 해석하여
        # 공격자가 서버 내부 파일(/etc/passwd 등)을 탈취하거나 SSRF를 유발할 수 있음.
        # defusedxml은 외부 엔티티 참조, DTD 처리 등을 원천 차단함.
        root = ET.fromstring(xml_data)
        amount = root.find('amount').text
        return {"status": "success", "amount_processed": amount}
    except ET.DefusedXmlException:
        return {"status": "error", "message": "보안상 허용되지 않는 XML 형식입니다."}, 400
    except Exception as e:
        return {"status": "error", "message": "잘못된 XML 형식입니다."}

if __name__ == '__main__':
    app.run()