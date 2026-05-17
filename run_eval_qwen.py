"""run_eval_qwen.py (v3) — Qwen 2.5-Coder + Tree-sitter + RAG + MITRE"""
import time, ollama
from config import MODEL_QWEN_RAG, OLLAMA_QWEN
from rag_engine import RAGEngine
from utils.eval_utils import extract_predicted_cwe, get_memory_mb
from utils.prompts import build_rag_prompt, build_safe_check_prompt
from utils.eval_loop import run_eval_loop

def main():
    print(f"=== 🚀 [{MODEL_QWEN_RAG}] 초기화 ===")
    rag = RAGEngine()

    def evaluate(code: str, is_patch: bool = False) -> tuple:
        rag_ctx, mitre_ctx = rag.get_context(code)

        if is_patch:
            # 패치 파일: RAG 컨텍스트 있어도 safe_check 프롬프트 사용
            prompt = build_safe_check_prompt(
                code, use_rag=bool(rag_ctx),
                rag_context=rag_ctx, mitre_context=mitre_ctx
            )
        else:
            if not rag_ctx:
                return ("SKIPPED", 0.0, 0.0, "DB 매칭 없음")
            prompt = build_rag_prompt(code, rag_ctx, mitre_ctx)

        start = time.time(); mem0 = get_memory_mb()
        try:
            resp = ollama.chat(model=OLLAMA_QWEN, messages=[{'role': 'user', 'content': prompt}])
            text = resp['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (extract_predicted_cwe(text), round(time.time()-start,2), round(get_memory_mb()-mem0,2), text[:80])

    run_eval_loop(MODEL_QWEN_RAG, evaluate, memory_label="MB")

if __name__ == "__main__":
    main()
