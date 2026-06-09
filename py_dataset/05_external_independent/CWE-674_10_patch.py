def resolve_comment_thread(comment_id: str, replies: dict[str, list[str]]) -> list[str]:
    visited_nodes = set()

    def _resolve_comment_thread_recursive(current_id: str, all_replies: dict[str, list[str]], current_visited: set) -> list[str]:
        # If this node has already been visited in the current path, it indicates a cycle.
        # Return an empty list to break the recursion for this path.
        if current_id in current_visited:
            return []

        # Mark the current node as visited for the current path.
        current_visited.add(current_id)

        flattened = [current_id]
        for reply_id in all_replies.get(current_id, []):
            # Pass the same `current_visited` set to propagate visited state across recursive calls.
            flattened.extend(_resolve_comment_thread_recursive(reply_id, all_replies, current_visited))
        
        # After processing all children of current_id, remove it from visited_nodes
        # if this is part of a non-cyclic path where a node can be part of multiple trees.
        # However, for simple cycle detection in a single thread flattening, leaving it in is also fine
        # as it prevents re-processing if a node appears multiple times in different branches (like a DAG).
        # For this specific problem (flattening a thread, typically a tree or DAG with potential cycles),
        # removing it here might allow re-processing in a different branch,
        # which isn't the desired behavior for a "flattened" list without duplicates due to different paths.
        # Keeping it in `current_visited` ensures a node is added to `flattened` only once per top-level call.
        
        return flattened

    # Start the recursion with the initial comment_id and the shared visited_nodes set.
    return _resolve_comment_thread_recursive(comment_id, replies, visited_nodes)
