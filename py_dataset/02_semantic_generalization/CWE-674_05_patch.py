class WorkflowEvaluator:
    def resolve(self, step_id: str, transitions: dict[str, list[str]]) -> list[str]:
        # Inner helper function to perform the recursive traversal with path tracking.
        # This prevents uncontrolled recursion (CWE-674) by detecting cycles.
        def _recursive_resolve(current_step: str, current_transitions: dict[str, list[str]], path: list[str]) -> list[str]:
            # CWE-674 fix: Detect cycles in the current path to prevent infinite recursion
            if current_step in path:
                # Cycle detected. Return an empty list for this branch to stop traversal
                # and prevent infinite recursion or a stack overflow.
                return []

            # Add the current step to the path for subsequent recursive calls
            # Create a new list for the next path to avoid modifying the 'path' list
            # from previous recursive calls.
            next_path = path + [current_step]

            # Initialize the sequence for the current step
            sequence = [current_step]

            # Recursively resolve for each next step
            for next_s in current_transitions.get(current_step, []):
                sequence.extend(_recursive_resolve(next_s, current_transitions, next_path))
            return sequence

        # Start the recursive process with an empty path
        return _recursive_resolve(step_id, transitions, [])

def preview_workflow(payload: dict) -> list[str]:
    return WorkflowEvaluator().resolve(payload["start"], payload["transitions"])
