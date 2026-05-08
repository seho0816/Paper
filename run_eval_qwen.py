import os
import datetime
import re
from config import TEST_DIR
from rag_engine import RAGEngine
from ollama_evaluator import evaluate

# 💡 이 파일에서 테스트할 모델 이름만 딱 지정해 주면 됩니다!
TARGET_MODEL = 'qwen2.5-coder'

def main():
    print(f"=== 🚀 [{TARGET_MODEL}] 전용 자동 평가 시스템 시작 ===")
    rag = RAGEngine()
    RESULT_DIR = 'result_integrated'
    
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    # 단일 모델 통계 저장소
    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    total_files = len(test_files)
    
    print(f"\n⏳ [{TARGET_MODEL}] 모델 평가 진행 중... (총 {total_files}개 파일)")
    
    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)
        
        # 파일명에서 3~4자리 숫자를 찾아 정답 추출
        matches = re.findall(r'\d{3,4}', filename)
        ground_truth_cwes = [f"CWE-{m}" for m in matches]
        
        if not ground_truth_cwes:
            print("⚠️ 무시됨 (CWE 번호 없음)")
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
            
        rag_context = rag.get_context(code_content)
        
        # 💡 하나의 모델만 평가 함수로 넘김
        result = evaluate(TARGET_MODEL, code_content, rag_context, ground_truth_cwes)
        
        # 결과 실시간 출력
        if 'TP' in result['eval_result']:
            model_stats['Correct'] += 1
            print(f"✅ 정답 ({result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            # 💡 [핵심] 오답일 경우 AI가 실제로 뭐라고 대답했는지 원본 텍스트의 앞부분을 잘라서 보여줍니다.
            raw_head = result['raw_response'].replace('\n', ' ').strip()[:50]
            print(f"❌ 오답 ({result['inference_time']}s) -> AI실제답변: {raw_head}...")
            
        model_stats['total_time'] += result['inference_time']
        
        log_str = f"📄 {filename} | 정답: {ground_truth_cwes} | AI 예측: {result['prediction']} 👉 {result['eval_result']} | {result['inference_time']}s"
        model_stats['logs'].append(log_str)

    # 💡 파일 이름이 겹치지 않게 모델명을 넣어 리포트 저장
    report_filename = os.path.join(RESULT_DIR, f'Eval_{TARGET_MODEL}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TARGET_MODEL}] CWE 식별 정확도(Accuracy) 평가 리포트\n")
        rf.write(f"📁 총 평가 파일: {len(test_files)}개 | 🕒 일시: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        rf.write("=" * 60 + "\n\n")
        
        rf.write("| Model Name | Accuracy | Correct | Incorrect | Avg Time/File |\n")
        rf.write("|---|---|---|---|---|\n")

        correct = model_stats['Correct']
        incorrect = model_stats['Incorrect']
        total = correct + incorrect
        
        accuracy = (correct / total * 100) if total > 0 else 0
        avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0
        
        rf.write(f"| {TARGET_MODEL} | **{accuracy:.1f}%** | {correct} | {incorrect} | {avg_time}s |\n\n")

        rf.write("=" * 60 + "\n")
        rf.write("📝 개별 파일 분석 상세 로그\n")
        rf.write("=" * 60 + "\n\n")

        for log in model_stats['logs']:
            rf.write(log + "\n")

    print(f"\n✅ 평가 완료! 결과 리포트가 '{report_filename}'에 저장되었습니다.")

if __name__ == "__main__":
    main()