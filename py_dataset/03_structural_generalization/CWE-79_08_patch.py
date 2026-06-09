from dataclasses import dataclass

from flask import Flask, request, escape

app = Flask(__name__)


@dataclass(frozen=True)
class Comment:
    author: str
    body: str


class CommentRepository:
    def __init__(self) -> None:
        self._comments: list[Comment] = []

    def save(self, comment: Comment) -> None:
        self._comments.append(comment)

    def find_all(self) -> list[Comment]:
        return list(self._comments)


class CommentPageBuilder:
    def build(self, comments: list[Comment]) -> str:
        page = "<html><body>"
        for comment in comments:
            page += (
                "<h3>" + escape(comment.author) + "</h3>"
                "<div>" + escape(comment.body) + "</div>"
            )
        return page + "</body></html>"


repository = CommentRepository()
builder = CommentPageBuilder()


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        repository.save(
            Comment(
                author=request.form.get("author", ""),
                body=request.form.get("body", ""),
            )
        )

    return builder.build(repository.find_all())
