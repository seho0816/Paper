import os
import datetime
import re
from config import MODELS, TEST_DIR
from rag_engine import RAGEngine
from ollama_evaluator import evaluate

def main():
    print("=== 🚀 RAG 통합 자동 평가 시스템 (실시간 진행률 표시) 시작 ===")
    rag = RAGEngine()
    RESULT_DIR = 'result_integrated'
    
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {model: {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []} for model in MODELS}

    for model in MODELS:
        total_files = len(test_files)
        print(f"\n⏳ [{model}] 모델 평가 진행 중... (총 {total_files}개 파일)")
        
        # 💡 enumerate를 사용하여 현재 몇 번째 인덱스인지(idx) 추적합니다.
        for idx, filename in enumerate(test_files, start=1):
            file_path = os.path.join(TEST_DIR, filename)
            
            # 💡 [핵심] 진행률 계산 및 출력 (end='' 를 써서 줄바꿈 없이 출력)
            progress = (idx / total_files) * 100
            print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)
            
            # 💡 파일명에서 3~4자리 숫자를 모두 찾아내서 앞에 'CWE-'를 붙여 정답지로 만듭니다!
            # 이제 CWE-117_532_Test.py 에서 ['CWE-117', 'CWE-532'] 두 개를 완벽하게 찾아냅니다.
            matches = re.findall(r'\d{3,4}', filename)
            ground_truth_cwes = [f"CWE-{m}" for m in matches]
            
            if not ground_truth_cwes:
                print(f"⚠️ 무시됨 (CWE 번호 없음)")
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
                
            rag_context = rag.get_context(code_content)
            result = evaluate(model, code_content, rag_context, ground_truth_cwes)
            
            # 💡 [핵심] AI 분석이 끝나면 같은 줄에 채점 결과를 이어서 출력합니다!
            if 'TP' in result['eval_result']:
                model_stats[model]['Correct'] += 1
                print(f"✅ 정답 ({result['inference_time']}s)")
            else:
                model_stats[model]['Incorrect'] += 1
                print(f"❌ 오답 ({result['inference_time']}s)")
                
            model_stats[model]['total_time'] += result['inference_time']
            
            log_str = f"📄 {filename} | 정답 후보: {ground_truth_cwes} | AI 예측: {result['prediction']} 👉 {result['eval_result']} | {result['inference_time']}s"
            model_stats[model]['logs'].append(log_str)

    report_filename = os.path.join(RESULT_DIR, f'Eval_Report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("======================================================================\n")
        rf.write("📊 CWE 식별 정확도(Accuracy) 평가 결과 표\n")
        rf.write(f"📁 총 평가 파일: {len(test_files)}개 | 🕒 일시: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        rf.write("======================================================================\n")
        
        rf.write("| Model Name | Accuracy | Correct | Incorrect | Avg Time/File |\n")
        rf.write("|---|---|---|---|---|\n")

        for model in MODELS:
            stats = model_stats[model]
            correct = stats['Correct']
            incorrect = stats['Incorrect']
            total = correct + incorrect
            
            accuracy = (correct / total * 100) if total > 0 else 0
            avg_time = round(stats['total_time'] / total, 2) if total > 0 else 0
            
            rf.write(f"| {model} | **{accuracy:.1f}%** | {correct} | {incorrect} | {avg_time}s |\n")

        rf.write("\n\n======================================================================\n")
        rf.write("📝 개별 파일 분석 상세 로그\n")
        rf.write("======================================================================\n\n")

        for model in MODELS:
            rf.write(f"--- 🔍 [{model}] 상세 분석 내역 ---\n")
            for log in model_stats[model]['logs']:
                rf.write(log + "\n")
            rf.write("\n")

    print(f"\n✅ 평가 완료! CWE 분류 정확도가 계산된 리포트가 '{report_filename}'에 저장되었습니다.")

if __name__ == "__main__":
    main()