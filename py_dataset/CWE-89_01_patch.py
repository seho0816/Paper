from flask import request
from sqlalchemy import text
from app import db

def search_posts():
    keyword = request.args.get("q", "")
    # Use parameterized query to prevent SQL injection (CWE-89)
    # The 'text' construct in SQLAlchemy supports named parameters prefixed with a colon.
    # The wildcard characters '%' must be part of the parameter value, not the SQL string itself,
    # for proper handling by the database driver.
    sql = text("SELECT id, title FROM posts WHERE title LIKE :search_keyword")
    return db.session.execute(sql, {"search_keyword": f"%{keyword}%"}).fetchall()
