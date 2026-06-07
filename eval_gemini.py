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

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch(code) if is_patch else build_raw(code)
        start = time.time()
        try:
            r = _client.models.generate_content(
                model=GEMINI_MODEL, contents=prompt)
            text = r.text if r.text is not None else ""
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_gemini.py
    # 앞에서 N개만:        python eval_gemini.py --limit 10
    # 무작위 N쌍 샘플:     python eval_gemini.py --sample 5
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="gemini 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_GEMINI_RAW, evaluate, "gemini",
        limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()