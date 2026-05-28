"""eval_grok.py — 비교군 ②: Grok 3 Mini, 순수 LLM"""
import os, time
from openai import OpenAI
from dotenv import load_dotenv
from config import MODEL_GROK_RAW, GROK_MODEL
from utils.scoring import predicted_cwe
from utils.prompts import build_raw, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("GROK_API_KEY")
if not _key: print("GROK_API_KEY 없음"); exit()
# Grok은 OpenAI 호환 API 사용
_client = OpenAI(api_key=_key, base_url="https://api.x.ai/v1")

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch(code) if is_patch else build_raw(code)
        start = time.time()
        try:
            r = _client.chat.completions.create(
                model=GROK_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1024
            )
            text = r.choices[0].message.content
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_GROK_RAW, evaluate, "grok")

if __name__ == "__main__":
    main()