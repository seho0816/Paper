from flask import Flask, request
from urllib.parse import urlparse
import http.client

app = Flask(__name__)

@app.route('/pfp')
def pfp():
    url = urlparse(request.args.get('url'))
    conn = http.client.HTTPConnection(url.hostname, url.port)
    conn.request('GET', url.path)
    response = conn.getresponse()
    user.updateProfileImage(response.read())
    return response.read()

if __name__ == '__main__':
    app.run(port=3000)