def convert_user_document(document_path: str) -> str:
    worker = create_conversion_worker(
        run_as="document-worker",
        filesystem_scope="workspace-only",
        network_access=False,
    )
    return worker.convert(document_path)
