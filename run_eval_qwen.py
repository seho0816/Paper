import os
import datetime
import re
from config import TEST_DIR
from rag_engine import RAGEngine
from ollama_evaluator import evaluate

TARGET_MODEL = 'qwen2.5-coder'

def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 자동 평가 시스템 (Branch: feature/eval) ===")
    rag = RAGEngine()
    RESULT_DIR = 'result_integrated'
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    total_files = len(test_files)
    
    print(f"\n⏳ 평가 진행 중... (Dataset: {TEST_DIR})")
    
    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}'... ", end='', flush=True)
        
        matches = re.findall(r'\d{3,4}', filename)
        ground_truth_cwes = [f"CWE-{m}" for m in matches]
        
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
            
        rag_context = rag.get_context(code_content)
        result = evaluate(TARGET_MODEL, code_content, rag_context, ground_truth_cwes)
        
        if 'TP' in result['eval_result']:
            model_stats['Correct'] += 1
            print(f"✅ 정답 ({result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 ({result['inference_time']}s) -> AI대답: {result['raw_response']}")
            
        model_stats['total_time'] += result['inference_time']
        model_stats['logs'].append(f"📄 {filename} | 정답: {ground_truth_cwes} | 예측: {result['prediction']} | {result['eval_result']}")

    # 리포트 저장 로직 생략 (기존과 동일)
    print(f"\n✅ [{TARGET_MODEL}] 평가 완료!")

if __name__ == "__main__":
    main()