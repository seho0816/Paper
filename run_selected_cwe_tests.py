import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path
import os

def extract_final_cwe(output: str) -> str:
    matches = re.findall(r"<CWE>\s*(CWE-\d+)\s*</CWE>", output)
    if matches:
        return matches[-1]

    if "저장된 지식 범위 내에서 확정 가능한 취약점을 찾지 못했습니다" in output:
        return "NOT_FOUND"

    return "PARSE_FAILED"


def extract_direct_match_cwes(output: str) -> str:
    cwes = set()

    for match in re.findall(r"✅\s*(CWE-\d+)\s*직접 대응 확인", output):
        cwes.add(match)

    for match in re.findall(r"매칭 CWE=\['(CWE-\d+)'\]", output):
        cwes.add(match)

    for match in re.findall(r"CWE=\['(CWE-\d+)'\]", output):
        cwes.add(match)

    return ",".join(sorted(cwes))


def extract_top_vector_cwes(output: str, limit: int = 5) -> str:
    pairs = []

    for cwe, distance in re.findall(
        r"📍\s*\[청크\s*\d+\]\s*CWE=(CWE-\d+)\s*유사도 거리=([0-9.]+)",
        output,
    ):
        pairs.append((cwe, float(distance)))

    pairs.sort(key=lambda item: item[1])

    selected = []
    selected_cwes = set()

    for cwe, distance in pairs:
        if cwe in selected_cwes:
            continue

        selected.append((cwe, distance))
        selected_cwes.add(cwe)

        if len(selected) >= limit:
            break

    return ",".join(f"{cwe}:{distance:.4f}" for cwe, distance in selected)


def load_expected_rows(expected_csv: Path) -> list[dict[str, str]]:
    with expected_csv.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        fieldnames = set(reader.fieldnames or [])

    required = {"filename", "expected_cwe"}
    missing = required - fieldnames

    if missing:
        raise ValueError(f"expected_results.csv 필수 컬럼 누락: {sorted(missing)}")

    return rows


def run_analyzer_once(
    analyzer_script: Path,
    test_file: Path,
    python_executable: str,
    timeout_seconds: int,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    completed = subprocess.run(
        [python_executable, str(analyzer_script)],
        input=str(test_file) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        env=env,
    )

    return completed.returncode, completed.stdout or "", completed.stderr or ""


def write_raw_log(log_dir: Path, filename: str, stdout: str, stderr: str) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path = log_dir / f"{Path(filename).stem}.log"
    log_path.write_text(
        stdout + "\n\n" + "=" * 80 + "\n[STDERR]\n" + stderr,
        encoding="utf-8",
    )

    return log_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="expected_results.csv에 있는 CWE 테스트 파일만 선택 실행합니다."
    )
    parser.add_argument(
    "--analyzer",
    default=r"C:\Users\no121\Documents\논문\analyzer\analyzer_gemini_rag.py",
    help="기존 단일 파일 분석 스크립트 경로",
    )
    parser.add_argument(
        "--test-dir",
        default=r"C:\Users\no121\Documents\논문\cwe_added_without_tests_current_db",
        help="CWE 테스트 코드가 들어 있는 폴더 경로",
    )
    parser.add_argument(
        "--expected-csv",
        default=r"C:\Users\no121\Documents\논문\cwe_added_without_tests_current_db\expected_results.csv",
        help="expected_results.csv 경로",
    )
    parser.add_argument(
        "--output-csv",
        default=r"C:\Users\no121\Documents\논문\result\selected_cwe_test_results.csv",
        help="결과 CSV 저장 경로",
    )
    parser.add_argument(
        "--log-dir",
        default=r"C:\Users\no121\Documents\논문\result\selected_cwe_test_logs",
        help="각 테스트 원본 로그 저장 폴더",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="파일 1개당 제한 시간(초)",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="분석 스크립트를 실행할 Python 실행 파일",
    )

    args = parser.parse_args()

    analyzer_script = Path(args.analyzer)
    test_dir = Path(args.test_dir)
    expected_csv = Path(args.expected_csv)
    output_csv = Path(args.output_csv)
    log_dir = Path(args.log_dir)

    if not analyzer_script.exists():
        raise FileNotFoundError(f"분석 스크립트가 없습니다: {analyzer_script}")

    if not test_dir.exists():
        raise FileNotFoundError(f"테스트 폴더가 없습니다: {test_dir}")

    if not expected_csv.exists():
        raise FileNotFoundError(f"expected_results.csv가 없습니다: {expected_csv}")

    expected_rows = load_expected_rows(expected_csv)
    results = []

    print(f"선택 테스트 수: {len(expected_rows)}개")
    print(f"분석 스크립트: {analyzer_script}")
    print(f"테스트 폴더: {test_dir}")
    print()

    for index, row in enumerate(expected_rows, start=1):
        filename = row["filename"]
        expected_cwe = row["expected_cwe"]
        pattern_id = row.get("pattern_id", "")
        pattern = row.get("pattern", "")
        batch = row.get("batch", "")

        test_file = test_dir / filename

        print(f"[{index}/{len(expected_rows)}] {filename} 실행 중...")

        if not test_file.exists():
            result = {
                "filename": filename,
                "expected_cwe": expected_cwe,
                "final_cwe": "FILE_NOT_FOUND",
                "direct_match_cwes": "",
                "top_vector_cwes": "",
                "passed_by_final": False,
                "passed_by_direct": False,
                "passed": False,
                "return_code": "",
                "batch": batch,
                "pattern_id": pattern_id,
                "pattern": pattern,
                "log_path": "",
                "error": f"파일 없음: {test_file}",
            }
            results.append(result)
            print(f"  ❌ 파일 없음: {test_file}")
            continue

        try:
            return_code, stdout, stderr = run_analyzer_once(
                analyzer_script=analyzer_script,
                test_file=test_file,
                python_executable=args.python,
                timeout_seconds=args.timeout,
            )

            output = stdout + "\n" + stderr
            final_cwe = extract_final_cwe(output)
            direct_match_cwes = extract_direct_match_cwes(output)
            top_vector_cwes = extract_top_vector_cwes(output)
            log_path = write_raw_log(log_dir, filename, stdout, stderr)

            direct_set = set(filter(None, direct_match_cwes.split(",")))
            passed_by_final = final_cwe == expected_cwe
            passed_by_direct = expected_cwe in direct_set
            passed = passed_by_final or passed_by_direct

            result = {
                "filename": filename,
                "expected_cwe": expected_cwe,
                "final_cwe": final_cwe,
                "direct_match_cwes": direct_match_cwes,
                "top_vector_cwes": top_vector_cwes,
                "passed_by_final": passed_by_final,
                "passed_by_direct": passed_by_direct,
                "passed": passed,
                "return_code": return_code,
                "batch": batch,
                "pattern_id": pattern_id,
                "pattern": pattern,
                "log_path": str(log_path),
                "error": "",
            }

            results.append(result)

            mark = "✅" if passed else "⚠️"
            print(
                f"  {mark} expected={expected_cwe} "
                f"final={final_cwe} "
                f"direct=[{direct_match_cwes}] "
                f"passed={passed}"
            )

        except subprocess.TimeoutExpired:
            result = {
                "filename": filename,
                "expected_cwe": expected_cwe,
                "final_cwe": "TIMEOUT",
                "direct_match_cwes": "",
                "top_vector_cwes": "",
                "passed_by_final": False,
                "passed_by_direct": False,
                "passed": False,
                "return_code": "",
                "batch": batch,
                "pattern_id": pattern_id,
                "pattern": pattern,
                "log_path": "",
                "error": f"timeout over {args.timeout}s",
            }
            results.append(result)
            print(f"  ⏱️ TIMEOUT: {filename}")

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "filename",
        "expected_cwe",
        "final_cwe",
        "direct_match_cwes",
        "top_vector_cwes",
        "passed_by_final",
        "passed_by_direct",
        "passed",
        "return_code",
        "batch",
        "pattern_id",
        "pattern",
        "log_path",
        "error",
    ]

    with output_csv.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    passed_count = sum(1 for row in results if row["passed"])
    failed_count = total - passed_count

    print()
    print("=" * 80)
    print(f"선택 테스트 완료: {total}개")
    print(f"통과: {passed_count}개")
    print(f"확인 필요: {failed_count}개")
    print(f"결과 CSV: {output_csv}")
    print(f"원본 로그 폴더: {log_dir}")

    if failed_count:
        print()
        print("확인 필요 목록:")
        for row in results:
            if not row["passed"]:
                print(
                    f"- {row['filename']} "
                    f"expected={row['expected_cwe']} "
                    f"final={row['final_cwe']} "
                    f"direct=[{row['direct_match_cwes']}]"
                )


if __name__ == "__main__":
    main()
