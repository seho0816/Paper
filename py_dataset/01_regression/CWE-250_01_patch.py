def convert_user_document(document_path: str) -> str:
    # CWE-250: Execution with Unnecessary Privileges
    # The original code explicitly requested 'root' privileges, which is often unnecessary
    # for user document conversion and can lead to security risks.
    # The fix removes the 'run_as="root"' argument, assuming that 'create_conversion_worker'
    # without this argument will create a worker with appropriate, least-privilege permissions.
    worker = create_conversion_worker()
    return worker.convert(document_path)
