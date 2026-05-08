from flask import Flask, request, make_response

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    # VULNERABILITY: Reflecting any 'Origin' header back to the requester
    origin = request.headers.get('Origin')
    response.headers['Access-Control-Allow-Origin'] = origin or '*'
    
    # VULNERABILITY: Allowing cookies/auth headers with a reflected origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response