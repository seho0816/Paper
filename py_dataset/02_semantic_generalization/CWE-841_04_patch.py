import datetime

def current_time():
    return datetime.datetime.now()

def publish_submission(submission: dict) -> dict:
    # CWE-841: Improper Enforcement of an Expectation of Data Location
    # The original code directly modifies the input 'submission' dictionary.
    # To prevent unintended side effects on the caller's data or potential
    # exposure of sensitive information from the original object, a copy
    # of the dictionary is created. Modifications are then applied to this
    # new copy, ensuring the original submission remains unaltered.
    published_submission = submission.copy()
    published_submission['status'] = 'published'
    published_submission['published_at'] = current_time()
    return published_submission
