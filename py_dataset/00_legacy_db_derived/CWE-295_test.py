from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/fetch")
def fetch_data():
    api_url = request.args.get("url")

    response = requests.get(api_url, verify=False)

    return response.text