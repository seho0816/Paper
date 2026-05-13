import os
import datetime
import re
import time
import subprocess
import json
import csv
from config import TEST_DIR

TOOL_NAME = 'Bandit (SAST)'

def evaluate_with_bandit(file_path, ground_truth_cwes):
    start_time = time.time()
    predicted_cwes = []
    
    try:
        # Bandit 명령어를 백그라운드에서 실행 (JSON 포맷으로 결과 받기)
        result = subprocess.run(
            ['bandit', '-r', file_path, '-f', 'json', '-q'], 
            capture_output=True, 
            text=True
        )
        
        # 결과 JSON 파싱
        bandit_output = json.loads(result.stdout)
        
        # CWE 번호 추출
        for issue in bandit_output.get('results', []):
            cwe_info = issue.get('issue_cwe', {})
            if 'id' in cwe_info:
                predicted_cwes.append(f"CWE-{cwe_info['id']}")
                
        # 중복 제거
        predicted_cwes = list(set(predicted_cwes))
        
    except Exception as e:
        print(f"  [Error] Bandit 실행 중 에러: {e}")

    inference_time = round(time.time() - start_time, 2)
    
    # 예측 결과를 문자열로 변환 (없으면 None)
    pred_str = "/".join(predicted_cwes) if predicted_cwes else "None"
    
    # 채점 로직: 정답이 여러 개일 수 있으므로 교집합 확인 / 정답이 None이면 예측도 None이어야 함
    is_correct = False
    if ground_truth_cwes == ["None"] and pred_str == "None":
        is_correct = True  # 패치된 코드를 안전하다고 판별한 경우
    else:
        for pred_cwe in predicted_cwes:
            if pred_cwe in ground_truth_cwes:
                is_correct = True
                break
                
    eval_result = 'TP' if is_correct else 'FP'
        
    return {
        'prediction': pred_str, 
        'eval_result': eval_result,
        'inference_time': inference_time
    }

def main():
    print(f"=== 🚀 [{TOOL_NAME}] 논문용 데이터 수집 평가 시스템 시작 ===")
    RESULT_DIR = 'result_int'
    
    if not os.path.exists(RESULT_DIR): os.makedirs(RESULT_DIR)

    test_files = [f for f in os.listdir(TEST_DIR) if f.endswith('.py')]
    if not test_files:
        print(f"❌ '{TEST_DIR}' 폴더에 파이썬 파일이 없습니다.")
        return

    model_stats = {'Correct': 0, 'Incorrect': 0, 'total_time': 0, 'logs': []}
    csv_data = []
    
    total_files = len(test_files)
    print(f"\n⏳ [{TOOL_NAME}] 검사 진행 중... (총 {total_files}개 파일)")
    
    for idx, filename in enumerate(test_files, start=1):
        file_path = os.path.join(TEST_DIR, filename)
        
        progress = (idx / total_files) * 100
        print(f"  ▶ [{idx}/{total_files}] ({progress:.1f}%) '{filename}' 분석 중... ", end='', flush=True)
        
        matches = re.findall(r'CWE-\d{3,4}', filename, re.IGNORECASE)
        ground_truth_cwes = matches if matches else ["None"]
        
        # Bandit 평가 실행
        result = evaluate_with_bandit(file_path, ground_truth_cwes)
        
        gt_str = "/".join(ground_truth_cwes)
        match_ox = 'O' if result['eval_result'] == 'TP' else 'X'
        
        # 터미널 간략 출력
        if match_ox == 'O':
            model_stats['Correct'] += 1
            print(f"✅ 정답 (판정: {match_ox} | 시간: {result['inference_time']}s)")
        else:
            model_stats['Incorrect'] += 1
            print(f"❌ 오답 (판정: {match_ox} | 정답: {gt_str} 👉 예측: {result['prediction']} | 시간: {result['inference_time']}s)")
            
        model_stats['total_time'] += result['inference_time']
        
        csv_data.append({
            'Model': 'Bandit',
            'Filename': filename,
            'Ground_Truth': gt_str,
            'Prediction': result['prediction'],
            'Match': match_ox,
            'Time_s': result['inference_time'],
            'Memory_MB': 'CLI'
        })
        
        log_str = f"📄 {filename} | 정답: {gt_str:<10} | 예측: {result['prediction']:<10} | 판정: {match_ox} | 시간: {result['inference_time']}s"
        model_stats['logs'].append(log_str)

    now_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 1. 텍스트 리포트 저장
    report_filename = os.path.join(RESULT_DIR, f'Eval_Bandit_{now_str}.txt')
    with open(report_filename, mode='w', encoding='utf-8') as rf:
        rf.write("=" * 60 + "\n")
        rf.write(f"📊 [{TOOL_NAME}] CWE 식별 정확도 평가 리포트\n")
        rf.write("=" * 60 + "\n\n")
        
        correct = model_stats['Correct']
        accuracy = (correct / total_files * 100) if total_files > 0 else 0
        avg_time = round(model_stats['total_time'] / total_files, 2) if total_files > 0 else 0
        
        rf.write(f"| Accuracy: {accuracy:.1f}% | Correct: {correct} | Incorrect: {total_files-correct} | Avg Time: {avg_time}s |\n\n")
        
        rf.write("📝 상세 로그\n")
        rf.write("-" * 60 + "\n")
        for log in model_stats['logs']: 
            rf.write(log + "\n")

    # 2. 엑셀용 CSV 데이터 저장
    csv_filename = os.path.join(RESULT_DIR, f'Data_Bandit_{now_str}.csv')
    with open(csv_filename, mode='w', encoding='utf-8-sig', newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=['Model', 'Filename', 'Ground_Truth', 'Prediction', 'Match', 'Time_s', 'Memory_MB'])
        writer.writeheader()
        writer.writerows(csv_data)

    print(f"\n✅ 평가 완료! 요약 리포트: '{report_filename}'")
    print(f"📊 논문용 CSV 데이터가 '{csv_filename}'에 저장되었습니다!")

if __name__ == "__main__":
    main()