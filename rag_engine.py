"""
rag_engine.py
=============
RAG 컨텍스트 생성 모듈.  모든 run_eval_*_rag.py 가 이 클래스를 사용한다.

[처리 흐름]
  소스 코드
    │
    ▼  Tree-sitter 청킹
  [module_context, func1, func2, ...]
    │
    ▼  청크별 ChromaDB 벡터 검색
  retrieved_docs  +  mitre_candidate_cwes
    │
    ▼  MITRE JSON exact lookup
  mitre_context (공식 CWE 설명)
    │
    ▼  build_prompt_context()
  프롬프트에 삽입할 최종 컨텍스트 문자열
"""

import os
import json
import re
import chromadb
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

from config import (
    DB_DIR, COLLECTION_NAME, MITRE_JSON_PATH,
    DISTANCE_THRESHOLD, MAX_RETRIEVAL_K, MITRE_TOP_K_PER_CHUNK
)


class RAGEngine:
    """
    Tree-sitter 청킹 + ChromaDB 벡터 검색 + MITRE JSON 결합을 담당한다.

    사용법:
        rag = RAGEngine()
        rag_ctx, mitre_ctx = rag.get_context(source_code)
        # 둘 다 빈 문자열이면 DB 매칭 없음
    """

    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # ── ChromaDB ────────────────────────────────────────────
        db_path = os.path.join(current_dir, DB_DIR)
        self.db_client  = chromadb.PersistentClient(path=db_path)
        self.collection = self.db_client.get_collection(name=COLLECTION_NAME)

        # ── MITRE CWE JSON ──────────────────────────────────────
        mitre_path = os.path.join(current_dir, MITRE_JSON_PATH)
        try:
            with open(mitre_path, "r", encoding="utf-8-sig") as f:
                self.mitre_db: dict = json.load(f)
            print(f"  ✅ MITRE CWE JSON 로드 완료 ({len(self.mitre_db)}개 항목)")
        except FileNotFoundError:
            print(f"  ⚠️ MITRE JSON 없음: {mitre_path}")
            self.mitre_db = {}
        except json.JSONDecodeError as e:
            print(f"  ⚠️ MITRE JSON 파싱 오류: {e}")
            self.mitre_db = {}

        # ── Tree-sitter ─────────────────────────────────────────
        self._parser = Parser()
        self._parser.language = Language(tspython.language())

    # ────────────────────────────────────────────────────────────
    # Public API
    # ────────────────────────────────────────────────────────────

    def get_context(self, source_code: str) -> tuple[str, str]:
        """
        소스 코드를 청킹 → ChromaDB 검색 → MITRE 결합하여
        (rag_context, mitre_context) 튜플을 반환한다.

        두 값 모두 빈 문자열이면 DB 매칭 없음을 의미한다.
        """
        chunks = self._parse_and_chunk(source_code)

        db_size = self.collection.count()
        if db_size == 0:
            return "", ""

        k = min(MAX_RETRIEVAL_K, db_size)
        retrieved_docs:       set[str] = set()
        mitre_candidate_cwes: set[str] = set()

        for chunk in chunks:
            results = self.collection.query(query_texts=[chunk], n_results=k)
            if not (results.get('metadatas') and results['metadatas'][0]):
                continue

            distances = results['distances'][0]
            metadatas = results['metadatas'][0]

            for j, meta in enumerate(metadatas):
                if distances[j] >= DISTANCE_THRESHOLD:
                    continue

                # full_text 를 RAG 컨텍스트로 사용
                full_text = meta.get('full_text', '').strip()
                if full_text:
                    retrieved_docs.add(full_text)

                # 상위 N개 결과에서만 MITRE 후보 CWE 수집
                if j < MITRE_TOP_K_PER_CHUNK:
                    for cwe in re.findall(r'CWE-\d+', str(meta.get('cwe', ''))):
                        if cwe in self.mitre_db:
                            mitre_candidate_cwes.add(cwe)

        rag_context   = self._format_rag_context(retrieved_docs)
        mitre_context = self._format_mitre_context(mitre_candidate_cwes)

        return rag_context, mitre_context

    def has_match(self, source_code: str) -> bool:
        """DB 매칭 여부만 빠르게 확인한다 (RAG 스킵 판단용)."""
        rag_ctx, _ = self.get_context(source_code)
        return bool(rag_ctx)

    # ────────────────────────────────────────────────────────────
    # Tree-sitter 청킹
    # ────────────────────────────────────────────────────────────

    def _parse_and_chunk(self, source_code: str) -> list[str]:
        source_bytes = source_code.encode("utf-8")
        tree = self._parser.parse(source_bytes)
        root = tree.root_node

        chunks: list[str] = []

        # 전역 컨텍스트 (import, 전역 변수 등)
        module_ctx = self._extract_module_context(root, source_bytes)
        if module_ctx:
            chunks.append(module_ctx)

        # 함수 / 클래스 / 데코레이터 / main guard
        self._extract_callables(root, source_bytes, chunks)

        return chunks if chunks else [source_code]

    def _node_text(self, node, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8")

    def _is_main_guard(self, node, source_bytes: bytes) -> bool:
        text = self._node_text(node, source_bytes)
        return (
            node.type == "if_statement"
            and "__name__" in text
            and "__main__" in text
        )

    def _extract_module_context(self, root, source_bytes: bytes) -> str | None:
        """함수/클래스 바깥의 전역 구문들을 하나의 청크로 묶는다."""
        SKIP_TYPES = {"function_definition", "class_definition", "decorated_definition"}
        INCLUDE_TYPES = {
            "import_statement", "import_from_statement",
            "assignment", "expression_statement",
            "augmented_assignment", "comment",
        }
        parts: list[str] = []
        for child in root.children:
            if child.type in SKIP_TYPES:
                continue
            if child.type == "if_statement" and self._is_main_guard(child, source_bytes):
                continue
            if child.type in INCLUDE_TYPES:
                text = self._node_text(child, source_bytes).strip()
                if text:
                    parts.append(text)

        return ("# [MODULE_CONTEXT]\n" + "\n\n".join(parts)) if parts else None

    def _extract_callables(self, node, source_bytes: bytes, out: list[str]) -> None:
        """함수, 클래스, 데코레이터 포함 함수, main guard 블록을 추출한다."""
        if node.type == "decorated_definition":
            out.append(self._node_text(node, source_bytes))
            return
        if node.type in ("function_definition", "class_definition"):
            out.append(self._node_text(node, source_bytes))
            return
        if (node.type == "if_statement"
                and node.parent and node.parent.type == "module"
                and self._is_main_guard(node, source_bytes)):
            out.append(self._node_text(node, source_bytes))
            return
        for child in node.children:
            self._extract_callables(child, source_bytes, out)

    # ────────────────────────────────────────────────────────────
    # 포맷터
    # ────────────────────────────────────────────────────────────

    def _format_rag_context(self, docs: set[str]) -> str:
        if not docs:
            return ""
        return "\n\n".join(
            f"--- [Python 취약/개선 예시 {i+1}] ---\n{doc}"
            for i, doc in enumerate(docs)
        )

    def _format_mitre_context(self, cwes: set[str]) -> str:
        if not cwes:
            return "MITRE JSON에 등록된 공식 기준 정보는 없습니다."

        sections: list[str] = []
        for cwe in sorted(cwes):
            info = self.mitre_db.get(cwe)
            if not info:
                continue
            parent  = ", ".join(info.get("parent_cwe",  [])) or "없음"
            related = ", ".join(info.get("related_cwe", [])) or "없음"
            sections.append(
                f"--- [MITRE 공식 기준: {cwe}] ---\n"
                f"공식명: {info.get('official_title', '')}\n"
                f"추상화 수준: {info.get('abstraction', '')}\n"
                f"공식 요약: {info.get('summary_ko', '')}\n"
                f"공식 완화 방향: {info.get('mitigation_ko', '')}\n"
                f"상위 CWE: {parent}\n"
                f"관련 CWE: {related}\n"
                f"Python 메모: {info.get('python_note', '')}\n"
                f"출처: {info.get('source_url', '')}"
            )
        return "\n\n".join(sections) if sections else "MITRE JSON에 등록된 공식 기준 정보는 없습니다."
