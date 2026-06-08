from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get("q", "")

    # CWE-79: Cross-site Scripting (XSS) 취약점 방지
    # 사용자 입력 'keyword'를 HTML 응답에 삽입하기 전에 escape 처리하여
    # 악의적인 스크립트 실행을 방지합니다.
    escaped_keyword = escape(keyword)

    html = f"""
    <html>
        <body>
            <h1>Search Result</h1>
            <p>검색어: {escaped_keyword}</p>
        </body>
    </html>
    """

    return make_response(html)


if __name__ == "__main__":
    app.run(debug=True)
