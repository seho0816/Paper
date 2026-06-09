import chromadb
from pathlib import Path
from datetime import datetime
import shutil
import re


CHROMA_DIR = "./rag_db"
COLLECTION_NAME = "python_security_lessons"

TARGET_ID = "snyk_lesson_cwe343_predictable_ids"
EXPECTED_CWE = "CWE-343"

AUTO_BACKUP = True


def extract_section_text(full_text: str, section_name: str) -> str:
    pattern = rf"\[{re.escape(section_name)}\]\s*(.*?)(?=\n\[[^\]]+\]|\Z)"
    match = re.search(pattern, full_text or "", re.DOTALL)
    return match.group(1).strip() if match else ""


def backup_db(chroma_dir: str) -> Path | None:
    source = Path(chroma_dir)

    if not source.exists():
        raise FileNotFoundError(
            f"ChromaDB 경로가 존재하지 않습니다: {source.resolve()}"
        )

    if not AUTO_BACKUP:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = (
        source.parent
        / f"{source.name}_backup_before_remove_cwe343_{timestamp}"
    )

    shutil.copytree(source, backup_path)
    print(f"[백업 완료] {backup_path.resolve()}")
    return backup_path


def load_target_document(collection) -> dict | None:
    result = collection.get(
        ids=[TARGET_ID],
        include=["documents", "metadatas"],
    )

    if not result["ids"]:
        return None

    metadata = result["metadatas"][0] or {}

    return {
        "id": result["ids"][0],
        "document": result["documents"][0] or "",
        "metadata": metadata,
        "cwe": metadata.get("cwe", ""),
        "full_text": metadata.get("full_text", ""),
    }


def main() -> None:
    chroma_path = Path(CHROMA_DIR)

    if not chroma_path.exists():
        raise FileNotFoundError(
            f"rag_db 폴더를 찾을 수 없습니다: {chroma_path.resolve()}"
        )

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    collection = client.get_collection(COLLECTION_NAME)

    before_count = collection.count()
    target = load_target_document(collection)

    print("=== CWE-343 문서 삭제 전 확인 ===")
    print(f"컬렉션: {COLLECTION_NAME}")
    print(f"삭제 전 문서 수: {before_count}")
    print(f"대상 ID: {TARGET_ID}")

    if target is None:
        print("대상 문서가 DB에 존재하지 않습니다. 삭제하지 않고 종료합니다.")
        return

    pattern_name = extract_section_text(
        target["full_text"],
        "취약점 명칭",
    )

    print(f"metadata.cwe: {target['cwe']}")
    print(f"취약점 명칭: {pattern_name or '(확인 불가)'}")

    if target["cwe"] != EXPECTED_CWE:
        raise ValueError(
            "삭제 대상의 CWE가 예상과 다릅니다. "
            f"예상={EXPECTED_CWE}, 실제={target['cwe']}. "
            "안전을 위해 삭제를 중단합니다."
        )

    backup_db(CHROMA_DIR)

    collection.delete(ids=[TARGET_ID])

    after_count = collection.count()
    remaining = load_target_document(collection)

    print()
    print("=== CWE-343 문서 삭제 결과 ===")
    print(f"삭제 전 문서 수: {before_count}")
    print(f"삭제 후 문서 수: {after_count}")
    print(f"문서 수 변화: {after_count - before_count}")

    if remaining is not None:
        raise RuntimeError(
            f"삭제 후에도 대상 ID가 남아 있습니다: {TARGET_ID}"
        )

    if after_count != before_count - 1:
        raise RuntimeError(
            "문서 수가 정확히 1개 감소하지 않았습니다. "
            f"삭제 전={before_count}, 삭제 후={after_count}"
        )

    print(f"삭제 완료: {TARGET_ID}")
    print("검증 완료: 대상 ID가 더 이상 존재하지 않습니다.")


if __name__ == "__main__":
    main()
