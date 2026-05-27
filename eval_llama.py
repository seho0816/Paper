"""eval_llama.py — 비교군 ②: Llama 3.2, 순수 LLM"""
import time, ollama
from config import MODEL_LLAMA_RAW, OLLAMA_LLAMA, OLLAMA_OPTIONS
from utils.scoring import predicted_cwe
from utils.prompts import build_raw_en, build_patch_en
from utils.loop import run

def evaluate(code, is_patch=False):
    prompt = build_patch_en(code) if is_patch else build_raw_en(code)
    start = time.time()
    try:
        r = ollama.chat(model=OLLAMA_LLAMA, messages=[{'role':'user','content':prompt}], options=OLLAMA_OPTIONS)
        text = r['message']['content']
    except Exception as e:
        text = f"Error: {e}"
    return (predicted_cwe(text), round(time.time()-start, 2))

if __name__ == "__main__":
    run(MODEL_LLAMA_RAW, evaluate)
