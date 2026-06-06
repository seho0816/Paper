from flask import request
from sqlalchemy import text
from app import db

def search_posts():
    keyword = request.args.get("q", "")
    sql = text(f"SELECT id, title FROM posts WHERE title LIKE '%{keyword}%'")
    return db.session.execute(sql).fetchall()
