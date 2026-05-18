"""eval_gemini.py — 비교군 ②: Gemini 2.5-Pro, 순수 LLM"""
import os, time
from google import genai
from dotenv import load_dotenv
from config import MODEL_GEMINI_RAW, GEMINI_MODEL
from utils.scoring import predicted_cwe
from utils.prompts import build_raw, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GEMINI_API_KEY")
if not _key: print("GEMINI_API_KEY 없음"); exit()
_client = genai.Client(api_key=_key)

def evaluate(code, is_patch=False):
    prompt = build_patch(code) if is_patch else build_raw(code)
    start = time.time()
    try:
        r = _client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        text = r.text
    except Exception as e:
        text = f"Error: {e}"
    return (predicted_cwe(text), round(time.time()-start, 2))

if __name__ == "__main__":
    run(MODEL_GEMINI_RAW, evaluate)
