import threading

class RenderingWorker:
    def __init__(
        self,
        semaphore: threading.Semaphore,
    ) -> None:
        self._semaphore = semaphore

    def handle(
        self,
        job: dict,
    ) -> None:
        self._semaphore.acquire()
        
        # This flag tracks if the job was successfully handed off to the asynchronous renderer.
        # If it was, the semaphore release will be handled by the on_success callback.
        # If submission failed synchronously, this flag remains True, and the finally block
        # will release the semaphore to prevent a resource leak.
        release_semaphore_on_submission_failure = True

        def on_success(
            result,
        ) -> None:
            # This function is called when the asynchronous rendering job completes.
            # It is responsible for saving the result and releasing the semaphore.
            save_render_result(
                job['id'],
                result,
            )
            self._semaphore.release() # This is the primary release point for successful async jobs

        try:
            renderer.submit(
                job,
                on_success=on_success,
            )
            # If we reach this line, the job was successfully submitted (queued)
            # to the asynchronous renderer.
            # Therefore, the semaphore release is now the responsibility of the `on_success` callback.
            # We must prevent the `finally` block from releasing it prematurely.
            release_semaphore_on_submission_failure = False

        finally:
            # This block executes regardless of whether an exception occurred during `renderer.submit`.
            # We only release the semaphore here if the job submission itself failed synchronously
            # (i.e., `release_semaphore_on_submission_failure` is still True).
            # This prevents a semaphore leak if `renderer.submit` fails,
            # and prevents a double release if `renderer.submit` succeeds.
            if release_semaphore_on_submission_failure:
                self._semaphore.release()
