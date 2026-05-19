"""
simple_rag_engine.py
비교군 ③: 라인 단위 청킹 RAG 엔진

[논문에서의 역할]
  계획서 3.2절 비교군 ③ "일반 RAG: 파서 분해 없이 단순 텍스트 라인 단위로
  Chunking한 일반 RAG + LLM" 에 해당한다.

  Tree-sitter 기반 rag_engine.py 와 다른 점은 청킹 방식뿐이다:
    - rag_engine.py    : 함수/클래스/모듈 단위 (구조적)
    - simple_rag_engine.py: N줄씩 자르기 (비구조적)

  ChromaDB, MITRE JSON 연동 방식은 동일하게 유지하여
  청킹 방법만 격리된 독립변수가 되도록 설계한다.
  이렇게 해야 "Tree-sitter 청킹이 X% 기여" 라는 주장이 타당해진다.
"""

import os
import json
import re
import chromadb

from config import (
    DB_DIR, COLLECTION_NAME, MITRE_JSON_PATH,
    DISTANCE_THRESHOLD, MAX_RETRIEVAL_K,
    MITRE_TOP_K_PER_CHUNK, SIMPLE_RAG_CHUNK_LINES
)


class SimpleRAGEngine:
    """
    라인 단위 청킹 + ChromaDB 벡터 검색 + MITRE JSON 결합.

    사용법:
        rag = SimpleRAGEngine()
        rag_ctx, mitre_ctx = rag.get_context(source_code)
    """

    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))

        db_path = os.path.join(current_dir, DB_DIR)
        self.db_client  = chromadb.PersistentClient(path=db_path)
        self.collection = self.db_client.get_collection(name=COLLECTION_NAME)

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

    def get_context(self, source_code: str) -> tuple[str, str, str]:
        """
        (rag_context, mitre_context, allowed_cwes) 3-tuple 반환.
        세 값 모두 빈 문자열이면 DB 매칭 없음.
        """
        chunks = self._line_chunk(source_code)

        db_size = self.collection.count()
        if db_size == 0:
            return "", "", ""

        k = min(MAX_RETRIEVAL_K, db_size)
        retrieved_docs:       set[str] = set()
        mitre_candidate_cwes: set[str] = set()
        all_candidate_cwes:   set[str] = set()

        for chunk in chunks:
            if not chunk.strip():
                continue
            results = self.collection.query(query_texts=[chunk], n_results=k)
            if not (results.get('metadatas') and results['metadatas'][0]):
                continue

            distances = results['distances'][0]
            metadatas = results['metadatas'][0]

            for j, meta in enumerate(metadatas):
                if distances[j] >= DISTANCE_THRESHOLD:
                    continue

                full_text = meta.get('full_text', '').strip()
                if full_text:
                    retrieved_docs.add(full_text)

                for cwe in re.findall(r'CWE-\d+', str(meta.get('cwe', ''))):
                    all_candidate_cwes.add(cwe)
                    if j < MITRE_TOP_K_PER_CHUNK and cwe in self.mitre_db:
                        mitre_candidate_cwes.add(cwe)

        rag_context   = self._format_rag(retrieved_docs)
        mitre_context = self._format_mitre(mitre_candidate_cwes)
        allowed_cwes  = ", ".join(sorted(all_candidate_cwes)) if all_candidate_cwes else "없음"
        return rag_context, mitre_context, allowed_cwes

    def _line_chunk(self, source_code: str) -> list[str]:
        """
        소스 코드를 SIMPLE_RAG_CHUNK_LINES 줄씩 단순 분할.
        빈 줄만 있는 청크는 제외.
        """
        lines  = source_code.splitlines()
        chunks = []
        step   = SIMPLE_RAG_CHUNK_LINES

        for i in range(0, len(lines), step):
            chunk = "\n".join(lines[i:i + step])
            if chunk.strip():
                chunks.append(chunk)

        return chunks if chunks else [source_code]

    def _format_rag(self, docs: set[str]) -> str:
        if not docs:
            return ""
        return "\n\n".join(
            f"--- [Python 취약/개선 예시 {i+1}] ---\n{doc}"
            for i, doc in enumerate(docs)
        )

    def _format_mitre(self, cwes: set[str]) -> str:
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
                f"공식 요약: {info.get('summary_ko', '')}\n"
                f"공식 완화 방향: {info.get('mitigation_ko', '')}\n"
                f"상위 CWE: {parent}\n"
                f"관련 CWE: {related}\n"
                f"Python 메모: {info.get('python_note', '')}"
            )
        return "\n\n".join(sections) if sections else "MITRE JSON에 등록된 공식 기준 정보는 없습니다."

    def get_context_local(self, source_code: str) -> tuple[str, str, str]:
        """로컬 소형 모델 전용: RAG 컨텍스트를 영어 요약으로 압축."""
        rag_ctx, mitre_ctx, allowed_cwes = self.get_context(source_code)
        if not rag_ctx:
            return "", "", ""
        return (
            self._summarize_rag(rag_ctx),
            self._summarize_mitre(mitre_ctx),
            allowed_cwes
        )

    def _summarize_rag(self, rag_ctx: str) -> str:
        import re
        summaries = []
        blocks = rag_ctx.split('--- [Python')
        for block in blocks:
            if not block.strip():
                continue
            cwe_match = re.search(r'CWE-\d+', block)
            cwe = cwe_match.group() if cwe_match else "Unknown"
            name_match = re.search(r'\[취약점 명칭\]\s*(.+)', block)
            name = name_match.group(1).strip()[:60] if name_match else cwe
            summaries.append(f"[{cwe}] {name}")
        return "\n".join(summaries) if summaries else rag_ctx[:200]

    def _summarize_mitre(self, mitre_ctx: str) -> str:
        import re
        lines = []
        for line in mitre_ctx.split('\n'):
            if 'MITRE 공식 기준' in line or '공식명' in line or '출처' in line:
                clean = re.sub(r'[-\[\]]', '', line).strip()
                if clean:
                    lines.append(clean)
        return "\n".join(lines[:6]) if lines else ""