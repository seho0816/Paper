"""eval_qwen.py — 비교군 ②: Qwen 2.5-Coder, 순수 LLM"""
import time, ollama
from config import MODEL_QWEN_RAW, OLLAMA_QWEN, OLLAMA_OPTIONS
from utils.scoring import predicted_cwe
from utils.prompts import build_raw, build_patch
from utils.loop import run

def evaluate(code, is_patch=False):
    prompt = build_patch(code) if is_patch else build_raw(code)
    start = time.time()
    try:
        r = ollama.chat(model=OLLAMA_QWEN, messages=[{'role':'user','content':prompt}], options=OLLAMA_OPTIONS)
        text = r['message']['content']
    except Exception as e:
        text = f"Error: {e}"
    return (predicted_cwe(text), round(time.time()-start, 2))

if __name__ == "__main__":
    run(MODEL_QWEN_RAW, evaluate)
