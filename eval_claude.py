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
                model=CLAUDE_MODEL, max_tokens=1024, temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )
            text = msg.content[0].text
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_claude.py
    # 앞에서 N개만:        python eval_claude.py --limit 10
    # 무작위 N쌍 샘플:     python eval_claude.py --sample 5
    #   (--sample은 test/patch 쌍 단위로 무작위 선택 → 균형 보장)
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="eval_claude 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_CLAUDE_RAW, evaluate, "claude", limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()