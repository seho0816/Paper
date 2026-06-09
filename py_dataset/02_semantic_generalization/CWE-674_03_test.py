def render_category_tree(category_id: str, relations: dict[str, list[str]]) -> dict:
    children = [
        render_category_tree(child_id, relations)
        for child_id in relations.get(category_id, [])
    ]
    return {"id": category_id, "children": children}
