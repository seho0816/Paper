from flask import request

BASE_DIR = "/var/app/files"

def read_file():
    filename = request.args.get("filename")

    path = BASE_DIR + "/" + filename

    with open(path, "r", encoding="utf-8") as f:
        return f.read()
