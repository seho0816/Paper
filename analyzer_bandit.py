import os
import datetime

print("=== Bandit 정적 보안 분석 자동화 스크립트 ===")
print("분석할 파일의 경로를 입력하세요. (예: bandit_test/CWE-338_CWE-343test.py)")
print("종료하려면 'exit'을 입력하세요.")

while True:
    print("\n[파일 경로 입력 대기 중...]")
    target_file = input("경로: ").strip()

    if target_file.lower() == 'exit':
        print("프로그램을 종료합니다.")
        break
        
    if not target_file:
        continue

    # 파일이 실제로 존재하는지 확인
    if not os.path.exists(target_file):
        print(f"⚠️ 오류: '{target_file}' 파일을 찾을 수 없습니다. 경로를 다시 확인해주세요.")
        continue

    # 1. result 폴더가 없으면 자동으로 생성
    os.makedirs("result", exist_ok=True)

    # 2. 원본 파일명 추출 및 저장할 파일명 조립
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # 예: bandit_test/CWE-942_testcode.py -> CWE-942_testcode 로 변환
    base_name = os.path.basename(target_file).replace('.py', '') 
    
    # 최종 파일명: result/result_bandit_CWE-942_testcode_20260422_151045.txt
    filename = os.path.join("result", f"result_bandit_{base_name}_{now}.txt")

    # Bandit 명령어 조립 및 실행
    print(f"\n🔍 Bandit 스캔 시작: {target_file}")
    
    # os.system 대신 os.popen을 사용하여 화면에도 출력하고 파일에도 저장
    command = f"bandit -f txt -o {filename} {target_file}"
    
    try:
        print("분석 중...")
        os.system(command)
        
        print("\n================ [Bandit 분석 결과 저장 완료] ================")
        print(f"✅ 분석 결과가 '{filename}' 파일에 성공적으로 저장되었습니다!")
        print("==============================================================\n")
        
        # 파일 내용을 읽어서 터미널에도 살짝 보여주기
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            show_lines = False
            print("--- [리포트 요약] ---")
            for line in lines:
                if "Test results:" in line:
                    show_lines = True
                if "Code scanned:" in line:
                    break
                if show_lines:
                    print(line.strip())
            print("---------------------\n")
            
    except Exception as e:
         print(f"오류 발생: {e}")