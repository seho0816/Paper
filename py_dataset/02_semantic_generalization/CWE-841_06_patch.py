import datetime

def current_time():
    """
    Returns the current datetime.
    This function is assumed to be available in the original context
    to make the provided snippet syntactically complete.
    """
    return datetime.datetime.now()

def activate_invited_member(membership: dict) -> dict:
    # CWE-841: Improper Enforcement of Behavioral Workflow
    # The original code allows any membership to be set to 'active' regardless of its
    # current status. A proper workflow dictates that a membership should only be
    # activated if it is in an 'invited' state. Attempting to activate an
    # already active, rejected, or otherwise invalid state membership is a workflow violation.

    # To fix CWE-841, we add a check to ensure the membership is in the
    # 'invited' status before proceeding with activation.
    if membership.get('status') == 'invited':
        membership['status'] = 'active'
        membership['joined_at'] = current_time()
        return membership
    else:
        # If the membership is not in the 'invited' state,
        # it means the activation cannot proceed due to workflow constraints.
        # We return the original (unmodified) membership dictionary to indicate
        # that the operation did not result in activation.
        return membership
