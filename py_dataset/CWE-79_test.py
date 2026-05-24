from flask import Flask, request, make_response

app = Flask(__name__)

messages = []

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        message = request.form.get("message")
        messages.append(message)

    html = "<html><body>"
    html += "<h1>Chat Room</h1>"

    for message in messages:
        html += "<div class='message'>" + message + "</div>"

    html += """
        <form method="POST">
            <input type="text" name="message">
            <button type="submit">Send</button>
        </form>
    """

    html += "</body></html>"

    return make_response(html)


if __name__ == "__main__":
    app.run(debug=True)