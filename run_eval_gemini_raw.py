"""run_eval_gemini_raw.py (v3) — Gemini 2.5-Pro, RAG 없음"""
import os, time
from google import genai
from dotenv import load_dotenv
from config import MODEL_GEMINI_RAW, GEMINI_MODEL
from utils.eval_utils import extract_predicted_cwe
from utils.prompts import build_raw_prompt, build_safe_check_prompt
from utils.eval_loop import run_eval_loop

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("❌ GEMINI_API_KEY 없음"); exit()
_client = genai.Client(api_key=_key)

def evaluate(code: str, is_patch: bool = False) -> tuple:
    prompt = build_safe_check_prompt(code) if is_patch else build_raw_prompt(code)
    start = time.time()
    try:
        resp = _client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        text = resp.text
    except Exception as e:
        text = f"Error: {e}"
    return (extract_predicted_cwe(text), round(time.time()-start,2), "API", text[:80])

if __name__ == "__main__":
    run_eval_loop(MODEL_GEMINI_RAW, evaluate, memory_label="API")
