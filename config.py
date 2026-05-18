"""
config.py
프로젝트 전역 설정. 값을 바꾸려면 이 파일 하나만 수정하면 된다.
"""

import os

# ── 모델 레이블 ───────────────────────────────────────────────
# 리포트 파일명 및 CSV의 Model 컬럼에 사용
MODEL_BANDIT          = "Bandit"

MODEL_QWEN_RAW        = "qwen2.5-coder_raw"
MODEL_LLAMA_RAW       = "llama3.2_raw"
MODEL_GEMINI_RAW      = "gemini-2.5-pro_raw"

MODEL_QWEN_SIMPLE_RAG  = "qwen2.5-coder_simple_rag"   # 비교군 ③: 라인 단위 청킹 RAG
MODEL_LLAMA_SIMPLE_RAG = "llama3.2_simple_rag"
MODEL_GEMINI_SIMPLE_RAG= "gemini-2.5-pro_simple_rag"

MODEL_QWEN_RAG        = "qwen2.5-coder_rag"           # 제안 모델 ④: Tree-sitter RAG
MODEL_LLAMA_RAG       = "llama3.2_rag"
MODEL_GEMINI_RAG      = "gemini-2.5-pro_rag"

# ── Ollama / Gemini 실제 모델 ID ──────────────────────────────
OLLAMA_QWEN  = "qwen2.5-coder"
OLLAMA_LLAMA = "llama3.2"
GEMINI_MODEL = "gemini-2.5-pro"

# ── 경로 ─────────────────────────────────────────────────────
TEST_DIR        = "py_dataset"
KNOWLEDGE_DIR   = "knowledge"
DB_DIR          = "rag_db"
RESULT_DIR      = "result_int"
MITRE_JSON_PATH = os.path.join(KNOWLEDGE_DIR, "mitre_cwe_official.json")

# ── ChromaDB ──────────────────────────────────────────────────
COLLECTION_NAME = "python_security_lessons"

# ── RAG 검색 파라미터 ─────────────────────────────────────────
DISTANCE_THRESHOLD    = 1.8
MAX_RETRIEVAL_K       = 7
MITRE_TOP_K_PER_CHUNK = 2

# ── Simple RAG 청킹 파라미터 ──────────────────────────────────
# 라인 단위 청킹: 몇 줄씩 자를지 (논문 비교군 ③용)
SIMPLE_RAG_CHUNK_LINES = 20

# ── Ollama 추론 옵션 ──────────────────────────────────────────
# [문제] num_ctx 미설정 시 Ollama가 모델 기본값(최대 128K) KV캐시를 잡아
#        로딩 및 연산에만 수백 초가 걸림. 우리 프롬프트는 최대 4K 토큰.
# [해결] num_ctx=4096 고정 → 불필요한 메모리/연산 차단, 5배+ 속도 향상
# [참고] num_predict: 모델이 생성하는 최대 출력 토큰. 분석 결과 500토큰 내외.
OLLAMA_OPTIONS = {
    "num_ctx":     4096,   # 컨텍스트 윈도우 고정 (토큰)
    "num_predict": 600,    # 최대 출력 토큰
}
