"""run_eval_llama_raw.py (v3) — Llama 3.2, RAG 없음"""
import time, ollama
from config import MODEL_LLAMA_RAW, OLLAMA_LLAMA
from utils.eval_utils import extract_predicted_cwe, get_memory_mb
from utils.prompts import build_raw_prompt, build_safe_check_prompt
from utils.eval_loop import run_eval_loop

def evaluate(code: str, is_patch: bool = False) -> tuple:
    prompt = build_safe_check_prompt(code) if is_patch else build_raw_prompt(code)
    start = time.time(); mem0 = get_memory_mb()
    try:
        resp = ollama.chat(model=OLLAMA_LLAMA, messages=[{'role': 'user', 'content': prompt}])
        text = resp['message']['content']
    except Exception as e:
        text = f"Error: {e}"
    return (extract_predicted_cwe(text), round(time.time()-start,2), round(get_memory_mb()-mem0,2), text[:80])

if __name__ == "__main__":
    run_eval_loop(MODEL_LLAMA_RAW, evaluate, memory_label="MB")
