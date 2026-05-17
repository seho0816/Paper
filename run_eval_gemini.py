"""run_eval_gemini.py (v3) — Gemini 2.5-Pro + Tree-sitter + RAG + MITRE"""
import os, time
from google import genai
from dotenv import load_dotenv
from config import MODEL_GEMINI_RAG, GEMINI_MODEL
from rag_engine import RAGEngine
from utils.eval_utils import extract_predicted_cwe
from utils.prompts import build_rag_prompt, build_safe_check_prompt
from utils.eval_loop import run_eval_loop

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("❌ GEMINI_API_KEY 없음"); exit()
_client = genai.Client(api_key=_key)

def main():
    print(f"=== 🚀 [{MODEL_GEMINI_RAG}] 초기화 ===")
    rag = RAGEngine()

    def evaluate(code: str, is_patch: bool = False) -> tuple:
        rag_ctx, mitre_ctx = rag.get_context(code)

        if is_patch:
            prompt = build_safe_check_prompt(
                code, use_rag=bool(rag_ctx),
                rag_context=rag_ctx, mitre_context=mitre_ctx
            )
        else:
            if not rag_ctx:
                return ("SKIPPED", 0.0, "API", "DB 매칭 없음")
            prompt = build_rag_prompt(code, rag_ctx, mitre_ctx)

        start = time.time()
        try:
            resp = _client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            text = resp.text
        except Exception as e:
            text = f"Error: {e}"
        return (extract_predicted_cwe(text), round(time.time()-start,2), "API", text[:80])

    run_eval_loop(MODEL_GEMINI_RAG, evaluate, memory_label="API")

if __name__ == "__main__":
    main()
