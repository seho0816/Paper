def search_my_documents(current_user_id: str, keyword: str) -> list[dict]:
    session = open_database_session(user=current_user_id)
    return session.search_documents(
        owner_id=current_user_id,
        keyword=keyword,
    )
