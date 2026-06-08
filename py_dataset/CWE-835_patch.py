import sys


def fetch_job_status(job_id: str) -> dict[str, str]:
    return {
        "job_id": job_id,
        "state": "running",
    }


class BatchJobWaiter:
    def wait_for_success(self, job_id: str) -> dict[str, str]:
        # CWE-835 fix: Introduce a maximum number of attempts to prevent an infinite loop.
        # This ensures the loop eventually terminates, even if the job never reaches a "succeeded" state.
        max_attempts = 100  # A reasonable arbitrary limit for this example.
        attempts = 0

        while attempts < max_attempts:
            status = fetch_job_status(job_id)

            if status["state"] == "succeeded":
                return status
            
            attempts += 1
        
        # If the loop completes because max_attempts was reached without the job succeeding,
        # return a status indicating failure to achieve success within the given attempts.
        return {
            "job_id": job_id,
            "state": "failed_timeout_or_unreachable",
        }


def read_job_id() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "JOB-100"


def main() -> None:
    waiter = BatchJobWaiter()
    print(waiter.wait_for_success(read_job_id()))


if __name__ == "__main__":
    main()
