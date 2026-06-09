class RenderingWorker:
    def __init__(
        self,
        semaphore,
    ) -> None:
        self._semaphore = semaphore

    def handle(
        self,
        job: dict,
    ) -> None:
        self._semaphore.acquire()

        def on_success(
            result,
        ) -> None:
            save_render_result(
                job['id'],
                result,
            )
            self._semaphore.release()

        try:
            renderer.submit(
                job,
                on_success=on_success,
            )
        finally:
            self._semaphore.release()
