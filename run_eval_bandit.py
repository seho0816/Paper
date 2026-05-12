import os
import datetime
import re
import time
import subprocess
import json
from config import TEST_DIR

TOOL_NAME = 'Bandit (SAST)'

def evaluate_with_bandit(file_path, ground_truth_cwes):
    start_time = time.time()
    
    try:
        # 💡 [핵심] 파이썬 내장 기능을 이용해 백그라운드에서 bandit 명령어를 실행합니다.
        # -f json: 결과를 읽기 쉽게 JSON 형태로 뽑아달라는 옵션
        # -q: 쓸데없는 로그 끄기
        result = subprocess.run(
            ['bandit', '-r', file_path, '-f', 'json', '-q'], 
            capture_output=True, 
            text=True
        )
        
        # Bandit이 만들어낸 JSON 결과물 읽기
        bandit_output = json.loads(result.stdout)
        
        predicted_cwes = []
        # Bandit이 찾은 취약점 목록에서 CWE 번호만 쏙쏙 뽑아냅니다.
        for issue in bandit_output.get('results', []):
            cwe_info = issue.get('issue_cwe', {})
            if 'id' in cwe_info:
                predicted_cwes.append(f"CWE-{cwe_info['id']}")
                
        # 중복 제거
        predicted_cwes = list(set(predicted_cwes))
        
    except Exception as e:
        predicted_cwes = []
        print(f"  [Error] Bandit 실행 중 에러: {e}")

    inference_time = round(time.time() - start_time, 2)
    
    # 💡 채점 로직: Bandit이 찾은 CWE 중 하나라도 정답지에 있으면 정답(TP)!
    is_correct = False
    for pred_cwe in predicted_cwes:
        if pred_cwe in ground_truth_cwes:
            is_correct = True
            matched_cwe = pred_cwe
            break
            
    if is_correct:
        eval_result = f'TP (정답: {matched_cwe} 발견)'
        pred_str = str(predicted_cwes)
    else:
        pred_str = str(predicted_cwes) if predicted_cwes else "None"
        eval_result = f'FP (오답 - GT:{ground_truth_cwes} vs Pred:{pred_str})'
        
    return {
        'prediction': pred_str, 
        'eval_result': eval_result,
        'inference_time': inference_time
    }

def main():
    print(f"=== 🚀 [{TOOL_NAME}] 전용 자동 평가 시스템 시작 ===")
    RESULT_DIR = 'result_integrated'
    
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    total_files = len(test_files)
    
    print(f"\n⏳ [{TOOL_NAME}] 검사 진행 중... (총 {total_files}개 파일)")
    
    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)
        
        matches = re.findall(r'\d{3,4}', filename)
        ground_truth_cwes = [f"CWE-{m}" for m in matches]
        
        if not ground_truth_cwes:
            print("⚠️ 무시됨 (CWE 번호 없음)")
            continue
            
        # 💡 AI 대신 Bandit 평가 함수 호출!
        result = evaluate_with_bandit(file_path, ground_truth_cwes)
        
        if 'TP' in result['eval_result']:
            model_stats['Correct'] += 1
            print(f"✅ 정답 ({result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 ({result['inference_time']}s) -> 찾은 취약점: {result['prediction']}")
            
        model_stats['total_time'] += result['inference_time']
        
        log_str = f"📄 {filename} | 정답: {ground_truth_cwes} | Bandit 예측: {result['prediction']} 👉 {result['eval_result']} | {result['inference_time']}s"
        model_stats['logs'].append(log_str)

    report_filename = os.path.join(RESULT_DIR, f'Eval_Bandit_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TOOL_NAME}] CWE 식별 정확도(Accuracy) 평가 리포트\n")
        rf.write(f"📁 총 평가 파일: {len(test_files)}개 | 🕒 일시: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        rf.write("=" * 60 + "\n\n")
        
        rf.write("| Model Name | Accuracy | Correct | Incorrect | Avg Time/File |\n")
        rf.write("|---|---|---|---|---|\n")

        correct = model_stats['Correct']
        incorrect = model_stats['Incorrect']
        total = correct + incorrect
        
        accuracy = (correct / total * 100) if total > 0 else 0
        avg_time = round(model_stats['total_time'] / total, 2) if total > 0 else 0
        
        rf.write(f"| {TOOL_NAME} | **{accuracy:.1f}%** | {correct} | {incorrect} | {avg_time}s |\n\n")

        rf.write("=" * 60 + "\n")
        rf.write("📝 개별 파일 분석 상세 로그\n")
        rf.write("=" * 60 + "\n\n")

        for log in model_stats['logs']:
            rf.write(log + "\n")

    print(f"\n✅ 평가 완료! 결과 리포트가 '{report_filename}'에 저장되었습니다.")

if __name__ == "__main__":
    main()