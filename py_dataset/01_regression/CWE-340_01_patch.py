import secrets

def create_private_download(
    account_id: str,
    file_id: str,
) -> str:
    # CWE-340: Generation of Predictable Numbers or Identifiers.
    # The original `record_id` returned by `download_repository.insert`
    # is assumed to be a predictable identifier (e.g., an auto-incrementing integer).
    # To fix this, we generate a cryptographically secure, unpredictable token
    # and use it as the external download identifier.

    # Generate a cryptographically secure and unpredictable token.
    # secrets.token_urlsafe(32) generates a URL-safe text string of 32 bytes of randomness.
    download_token = secrets.token_urlsafe(32)

    # Insert the download record into the repository, including the generated unpredictable token.
    # The repository must be able to store and later retrieve this 'download_token'.
    # The return value of insert (the internal primary key 'record_id') is now ignored
    # for external identification purposes, as it is assumed to be predictable.
    download_repository.insert({
        'account_id': account_id,
        'file_id': file_id,
        'download_token': download_token, # Store the unpredictable token
    })
    
    # Return the generated unpredictable token as the download identifier.
    return f'DOWNLOAD-{download_token}'
