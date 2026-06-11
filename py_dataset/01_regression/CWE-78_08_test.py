from flask import request
import os

def backup_file():
    filename = request.args.get("file")

    command = "tar -czf backup.tar.gz " + filename
    os.system(command)

    return "backup complete"
