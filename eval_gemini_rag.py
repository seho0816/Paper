"""eval_gemini_rag.py — 비교군 ③: Gemini + 라인 단위 RAG"""
import os, time
from google import genai
from dotenv import load_dotenv
from config import MODEL_GEMINI_SIMPLE_RAG, GEMINI_MODEL
from rag_engine import SimpleRAGEngine
from utils.scoring import predicted_cwe
from utils.prompts import build_rag, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("GEMINI_API_KEY 없음"); exit()
_client = genai.Client(api_key=_key)

def main():
    print(f"=== [{MODEL_GEMINI_SIMPLE_RAG}] 초기화 (라인 단위 RAG) ===")
    rag = SimpleRAGEngine()

    def evaluate(code, is_patch=False):
        rag_ctx, mitre_ctx, allowed = rag.get_context(code)
        if is_patch:
            prompt = build_patch(code, rag_ctx, mitre_ctx)
        else:
            if not rag_ctx: return ("SKIPPED", 0.0)
            prompt = build_rag(code, rag_ctx, mitre_ctx, allowed)
        start = time.time()
        try:
            r = _client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            text = r.text
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_GEMINI_SIMPLE_RAG, evaluate)

if __name__ == "__main__":
    main()
