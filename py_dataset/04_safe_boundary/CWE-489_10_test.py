import os

from flask import Flask


app = Flask(__name__)
APPLICATION_ENV = os.environ.get(
    'APPLICATION_ENV',
    'production',
)


def start_server() -> None:
    app.run(
        host='127.0.0.1',
        port=8080,
        debug=(
            APPLICATION_ENV
            == 'development'
        ),
    )
