"""
프로젝트 전역 설정. 모든 run_eval_*.py 및 utils가 이 파일을 참조한다.
값을 바꾸려면 이 파일 하나만 수정하면 된다.
"""

import os

# ── 평가 대상 모델 레이블 ─────────────────────────────────────
# run_eval_*.py 에서 TARGET_MODEL 로 직접 사용하거나 리포트 파일명에 활용
MODEL_BANDIT      = "Bandit"
MODEL_QWEN_RAW    = "qwen2.5-coder_raw"
MODEL_LLAMA_RAW   = "llama3.2_raw"
MODEL_GEMINI_RAW  = "gemini-2.5-pro_raw"
MODEL_QWEN_RAG    = "qwen2.5-coder_rag"
MODEL_LLAMA_RAG   = "llama3.2_rag"
MODEL_GEMINI_RAG  = "gemini-2.5-pro_rag"

# Ollama 실제 모델 ID (ollama.chat 호출 시 사용)
OLLAMA_QWEN  = "qwen2.5-coder"
OLLAMA_LLAMA = "llama3.2"

# Gemini 실제 모델 ID
GEMINI_MODEL = "gemini-2.5-pro"

# ── 경로 설정 ─────────────────────────────────────────────────
TEST_DIR       = "py_dataset"    # 취약/패치 코드 데이터셋 폴더
KNOWLEDGE_DIR  = "knowledge"     # MITRE CWE JSON 폴더
DB_DIR         = "rag_db"        # ChromaDB 저장 폴더
RESULT_DIR     = "result_int"    # 실험 결과 저장 폴더

MITRE_JSON_PATH = os.path.join(KNOWLEDGE_DIR, "mitre_cwe_official.json")

# ── ChromaDB 설정 ─────────────────────────────────────────────
COLLECTION_NAME    = "python_security_lessons"

# ── RAG 검색 파라미터 ─────────────────────────────────────────
# DISTANCE_THRESHOLD: 이 값 이하인 거리의 문서만 컨텍스트로 사용
# (ChromaDB 기본 거리: L2. 낮을수록 유사도 높음)
DISTANCE_THRESHOLD   = 1.8   # analyzer_* 시리즈와 동일하게 통일
MAX_RETRIEVAL_K      = 7     # 청크당 검색 후보 수
MITRE_TOP_K_PER_CHUNK = 2   # MITRE 후보 CWE 수집: 상위 N개 결과만 사용