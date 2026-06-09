def resolve_comment_thread(comment_id: str, replies: dict[str, list[str]]) -> list[str]:
    flattened = [comment_id]
    for reply_id in replies.get(comment_id, []):
        flattened.extend(resolve_comment_thread(reply_id, replies))
    return flattened
