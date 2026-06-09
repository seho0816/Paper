def run_report_action(
    action_name: str,
):
    def rebuild():
        # Assumes rebuild_report_index() is defined and accessible in the global or enclosing scope.
        return rebuild_report_index()

    def purge():
        # Assumes purge_report_cache() is defined and accessible in the global or enclosing scope.
        return purge_report_cache()

    # Define a whitelist of allowed actions.
    # This prevents arbitrary function calls by restricting execution to explicitly permitted actions,
    # addressing the CWE-470 (Uncontrolled Consumption of Externally-Provided Code) vulnerability.
    safe_actions = {
        "rebuild": rebuild,
        "purge": purge,
    }

    # Safely retrieve the selected action from the whitelist.
    # If 'action_name' is not found in 'safe_actions', a KeyError will be raised,
    # preventing unintended or malicious execution.
    selected = safe_actions[action_name]

    return selected()
