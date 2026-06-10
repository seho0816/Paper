from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get("q", "")

    html = f"""
    <html>
        <body>
            <h1>Search Result</h1>
            <p>검색어: {keyword}</p>
        </body>
    </html>
    """

    return make_response(html)


if __name__ == "__main__":
    app.run(debug=True)