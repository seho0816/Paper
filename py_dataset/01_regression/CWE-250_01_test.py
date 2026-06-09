def convert_user_document(document_path: str) -> str:
    root_worker = create_conversion_worker(run_as="root")
    return root_worker.convert(document_path)
