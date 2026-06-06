"""
config.py
프로젝트 전역 설정. 값을 바꾸려면 이 파일 하나만 수정하면 된다.
"""
import os

# ── 모델 레이블 (CSV Model 컬럼 + 리포트 파일명) ──────────────
MODEL_BANDIT           = "Bandit"

MODEL_QWEN_RAW         = "qwen2.5-coder_raw"
MODEL_LLAMA_RAW        = "llama3.2_raw"
MODEL_GEMINI_RAW       = "gemini-2.5-pro_raw"
MODEL_CLAUDE_RAW       = "claude-sonnet-4-5_raw"
MODEL_GROK_RAW         = "grok-3-mini_raw"

MODEL_QWEN_SIMPLE_RAG  = "qwen2.5-coder_simple_rag"
MODEL_LLAMA_SIMPLE_RAG = "llama3.2_simple_rag"
MODEL_GEMINI_SIMPLE_RAG= "gemini-2.5-pro_simple_rag"
MODEL_CLAUDE_SIMPLE_RAG= "claude-sonnet-4-5_simple_rag"
MODEL_GROK_SIMPLE_RAG  = "grok-3-mini_simple_rag"

MODEL_QWEN_RAG_TS      = "qwen2.5-coder_rag_ts"
MODEL_QWEN_RAG         = MODEL_QWEN_RAG_TS
MODEL_LLAMA_RAG_TS     = "llama3.2_rag_ts"
MODEL_LLAMA_RAG        = MODEL_LLAMA_RAG_TS
MODEL_GEMINI_RAG_TS    = "gemini-2.5-pro_rag_ts"
MODEL_GEMINI_RAG       = MODEL_GEMINI_RAG_TS
MODEL_CLAUDE_RAG_TS    = "claude-sonnet-4-5_rag_ts"
MODEL_CLAUDE_RAG       = MODEL_CLAUDE_RAG_TS
MODEL_GROK_RAG_TS      = "grok-3-mini_rag_ts"
MODEL_GROK_RAG         = MODEL_GROK_RAG_TS

# ── 실제 모델 ID ──────────────────────────────────────────────
OLLAMA_QWEN  = "qwen2.5-coder"
OLLAMA_LLAMA = "llama3.2"
GEMINI_MODEL = "gemini-2.5-pro"
CLAUDE_MODEL = "claude-sonnet-4-5"
GROK_MODEL   = "grok-3-mini"

# ── 경로 ─────────────────────────────────────────────────────
TEST_DIR        = "py_dataset"
KNOWLEDGE_DIR   = "knowledge"
DB_DIR          = "rag_db"
RESULT_DIR      = "result"
MITRE_JSON_PATH = os.path.join(KNOWLEDGE_DIR, "mitre_cwe_official.json")

# ── ChromaDB ──────────────────────────────────────────────────
COLLECTION_NAME = "python_security_lessons"

# ── RAG 검색 파라미터 ─────────────────────────────────────────
# rag_ts_engine (Tree-sitter): 1.8 최적
#   → 구조적 청킹이라 청크가 적고, 임계값을 낮추면 매칭 문서가 급감
# rag_engine (Simple RAG):    1.4 최적
#   → 라인 단위 청킹이라 청크가 많고, 1.4에서 FP 감소 효과 확인 (0520 실험)
DISTANCE_THRESHOLD_TS     = 1.8   # Tree-sitter RAG 전용
DISTANCE_THRESHOLD_SIMPLE = 1.4   # Simple RAG 전용
DISTANCE_THRESHOLD        = 1.8   # 기본값 (하위 호환용)
MAX_RETRIEVAL_K            = 7
MITRE_TOP_K_PER_CHUNK      = 2

# ── Simple RAG 청킹 파라미터 ──────────────────────────────────
SIMPLE_RAG_CHUNK_LINES = 20

# ── Ollama 추론 옵션 ──────────────────────────────────────────
OLLAMA_OPTIONS = {
    "num_ctx":     4096,
    "num_predict": 1200,
}
OLLAMA_MAX_RETRIEVAL_K = 3