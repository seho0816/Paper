from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/v1/calculate', methods=['POST'])
def calculate():
    expression = request.json.get("expression")
    result = eval(expression)

    return jsonify({
        "expression": expression,
        "result": result
    })


if __name__ == "__main__":
    app.run(debug=True)