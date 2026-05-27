"""eval_claude.py — 비교군 ②: Claude, 순수 LLM"""
import os, time
import anthropic
from dotenv import load_dotenv
from config import MODEL_CLAUDE_RAW, CLAUDE_MODEL
from utils.scoring import predicted_cwe
from utils.prompts import build_raw, build_patch
from utils.loop import run

load_dotenv()
_key = os.getenv("CLAUDE_API_KEY")
if not _key: print("CLAUDE_API_KEY 없음"); exit()
_client = anthropic.Anthropic(api_key=_key)

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch(code) if is_patch else build_raw(code)
        start = time.time()
        try:
            msg = _client.messages.create(
                model=CLAUDE_MODEL, max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )
            text = msg.content[0].text
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    run(MODEL_CLAUDE_RAW, evaluate)

if __name__ == "__main__":
    main()