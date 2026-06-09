import re
import multiprocessing
import queue

class RegexTimeoutError(Exception):
    pass

def _split_document_worker(pattern: str, document: str, result_queue: multiprocessing.Queue):
    try:
        result = re.split(pattern, document)
        result_queue.put(result)
    except Exception as e:
        result_queue.put(e)

def split_document(
    pattern_text: str,
    document: str,
) -> list[str]:
    TIMEOUT_SECONDS = 1

    with multiprocessing.Manager() as manager:
        result_queue = manager.Queue()

        worker_process = multiprocessing.Process(
            target=_split_document_worker,
            args=(pattern_text, document, result_queue)
        )
        worker_process.daemon = True
        worker_process.start()

        try:
            result = result_queue.get(timeout=TIMEOUT_SECONDS)
        except queue.Empty:
            if worker_process.is_alive():
                worker_process.terminate()
                worker_process.join(timeout=0.1)
            raise RegexTimeoutError(f"Regular expression operation timed out after {TIMEOUT_SECONDS} seconds.")
        finally:
            if worker_process.is_alive():
                worker_process.terminate()
                worker_process.join(timeout=0.1)

        if isinstance(result, Exception):
            raise result

        return result
