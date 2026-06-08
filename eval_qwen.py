"""eval_qwen.py — 비교군 ②: Qwen 2.5-Coder, 순수 LLM"""
import time, ollama
from config import MODEL_QWEN_RAW, OLLAMA_QWEN, OLLAMA_OPTIONS
from utils.scoring import predicted_cwe
from utils.prompts import build_raw_en, build_patch_en
from utils.loop import run

def main():
    def evaluate(code, is_patch=False):
        prompt = build_patch_en(code) if is_patch else build_raw_en(code)
        start = time.time()
        try:
            r = ollama.chat(
                model=OLLAMA_QWEN,
                messages=[{'role':'user','content':prompt}],
                options=OLLAMA_OPTIONS
            )
            text = r['message']['content']
        except Exception as e:
            text = f"Error: {e}"
        return (predicted_cwe(text), round(time.time()-start, 2))

    # ── 실행 옵션 ──────────────────────────────────────────────
    # 전체 평가:           python eval_qwen.py
    # 앞에서 N개만:        python eval_qwen.py --limit 10
    # 무작위 N쌍 샘플:     python eval_qwen.py --sample 5
    # ────────────────────────────────────────────────────────────
    import argparse as _ap
    _p = _ap.ArgumentParser(description="qwen 평가")
    _p.add_argument('--limit',  type=int, default=0, help='앞에서 N개만 평가')
    _p.add_argument('--sample', type=int, default=0, help='무작위 N쌍 평가')
    _args = _p.parse_args()
    run(MODEL_QWEN_RAW, evaluate, "qwen",
        limit=_args.limit, sample=_args.sample)

if __name__ == "__main__":
    main()