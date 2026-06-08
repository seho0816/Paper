from flask import Flask, request, make_response
from markupsafe import escape # Import escape for XSS prevention

app = Flask(__name__)

messages = []

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        message = request.form.get("message")
        # Sanitize the message before appending to prevent storing raw potentially malicious input
        # Even though the main fix is during rendering, it's good practice to sanitize early if possible,
        # but for CWE-79, the key is sanitization before rendering.
        # Here, we'll sanitize during rendering to strictly adhere to the rule of fixing the *CWE-79* vulnerability.
        messages.append(message)

    html = "<html><body>"
    html += "<h1>Chat Room</h1>"

    for message in messages:
        # CWE-79 Fix: Escape user-provided content before rendering it into HTML.
        # This prevents Cross-Site Scripting (XSS) attacks.
        html += "<div class='message'>" + escape(message) + "</div>"

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
