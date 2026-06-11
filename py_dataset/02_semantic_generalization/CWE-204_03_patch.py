from fastapi import FastAPI, HTTPException

app = FastAPI()

# It is assumed that find_account is defined elsewhere and accessible,
# for example, in a database access layer. Its implementation is not
# part of the provided vulnerable code, so it is not modified or included here.
# It should return an account dictionary if found, or None otherwise.


@app.get("/api/recovery-question/{username}")
async def recovery_question(
    username: str,
) -> dict:
    # The original code had a CWE-204 (Observable Discrepancy) vulnerability.
    # It returned a 404 HTTP status code with "unknown username" detail
    # if the username did not exist. This allowed attackers to enumerate valid usernames.
    # To fix this, we ensure that the response for a non-existent username is
    # indistinguishable from a scenario where a username exists but no recovery question
    # is set, or for any other reason a question cannot be provided.

    account = find_account(username)

    # Initialize a generic response message. This message will be returned if
    # the user does not exist OR if the user exists but has no recovery question set.
    generic_question_response = "No recovery question is available for the provided details."

    if account is not None:
        # If an account is found, attempt to retrieve the actual recovery question.
        # Using .get() is safer as it handles cases where 'recovery_question' key
        # might be missing or its value is None, preventing KeyError/TypeError.
        actual_question = account.get("recovery_question")

        if actual_question:  # Check if a non-empty/truthy question is actually present
            return {
                "question": actual_question,
            }
        # If the account exists but 'actual_question' is None or an empty string,
        # we fall through and return the 'generic_question_response'.
        # This prevents an attacker from distinguishing between "user does not exist"
        # and "user exists but has no question".

    # If 'account is None' (user does not exist) or if 'account' exists but
    # 'actual_question' was not found/was empty, return the generic response.
    # The HTTP status code will implicitly be 200 OK, avoiding the 404 discrepancy.
    return {
        "question": generic_question_response,
    }
