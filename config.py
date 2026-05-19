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

MODEL_CLAUDE_RAW      = "claude-3-5-sonnet_raw"        # Claude API
MODEL_CLAUDE_RAG      = "claude-3-5-sonnet_rag"
MODEL_CLAUDE_RAG_TS   = "claude-3-5-sonnet_rag_ts"

# ── Ollama / Gemini / Claude 실제 모델 ID ─────────────────────
OLLAMA_QWEN  = "qwen2.5-coder"
OLLAMA_LLAMA = "llama3.2"
GEMINI_MODEL = "gemini-2.5-pro"
CLAUDE_MODEL = "claude-sonnet-4-5"                     # Anthropic API 모델 ID

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
# [문제] RAG 버전은 프롬프트가 ~2700토큰으로 길어서
#        num_predict=600 내에 <CWE> 태그까지 출력 못하는 현상 발생
# [해결] num_ctx=4096 유지, num_predict=1200으로 상향
#        → Analysis + Code + <CWE> 태그 전부 출력 가능
OLLAMA_OPTIONS = {
    "num_ctx":     4096,   # 컨텍스트 윈도우 고정 (토큰)
    "num_predict": 1200,   # 최대 출력 토큰 (RAG 버전: 분석+코드+태그 모두 필요)
}

# ── Ollama RAG 검색 수 제한 (로컬 모델 전용) ─────────────────
# RAG 버전에서 MAX_RETRIEVAL_K=7이면 프롬프트가 ~2700토큰
# 로컬 모델은 컨텍스트가 길수록 느려지므로 3으로 제한
OLLAMA_MAX_RETRIEVAL_K = 3