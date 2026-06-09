import os
import re
from collections import defaultdict

# 💡 데이터셋 최상위 폴더 경로 (필요시 수정하세요)
TARGET_DIR = "py_dataset"

def find_missing_pairs(base_dir):
    print(f"🔍 '{base_dir}' 폴더 내의 1:1 파일 짝 맞춤 검사를 시작합니다...\n")
    
    if not os.path.exists(base_dir):
        print(f"❌ 경로를 찾을 수 없습니다: {base_dir}")
        return

    total_missing_patch = 0
    total_missing_test = 0

    for root, dirs, files in os.walk(base_dir):
        # 04_safe_boundary 같은 단독 파일 폴더는 쌍 검사에서 제외
        if "04_" in root or "05_" in root:
            continue
            
        py_files = [f for f in files if f.endswith('.py')]
        if not py_files:
            continue
            
        # 딕셔너리로 파일 짝 기록 (예: {"CWE-79_01": {"test": "CWE-79_01_test.py"}})
        pairs = defaultdict(dict)
        
        for f in py_files:
            # _test.py 매칭 (예: CWE-123_test.py, CWE-123_test2.py)
            match_test = re.search(r'^(.*?)_test(\d*)\.py$', f, re.IGNORECASE)
            if match_test:
                stem = match_test.group(1) + match_test.group(2)
                pairs[stem]['test'] = f
                continue
                
            # _patch.py 매칭 (예: CWE-123_patch.py, CWE-123_patch2.py)
            match_patch = re.search(r'^(.*?)_patch(\d*)\.py$', f, re.IGNORECASE)
            if match_patch:
                stem = match_patch.group(1) + match_patch.group(2)
                pairs[stem]['patch'] = f
                continue

        # 누락된 파일 필터링
        missing_patch = []
        missing_test = []
        
        for stem, data in pairs.items():
            if 'test' in data and 'patch' not in data:
                missing_patch.append(data['test'])
            elif 'patch' in data and 'test' not in data:
                missing_test.append(data['patch'])
        
        # 결과 출력
        if missing_patch or missing_test:
            print(f"📂 [불일치 폴더] {root}")
            for f in missing_patch:
                print(f"   ❌ patch 누락 (test만 있음) : {f}")
                total_missing_patch += 1
            for f in missing_test:
                print(f"   ❌ test 누락 (patch만 있음): {f}")
                total_missing_test += 1
            print("-" * 50)

    print("\n📊 [최종 검사 결과]")
    if total_missing_patch == 0 and total_missing_test == 0:
        print("✅ 모든 파일이 완벽하게 1:1 짝을 이루고 있습니다!")
    else:
        print(f"⚠️ 총 {total_missing_patch}개의 파일이 패치(patch)가 누락되었습니다.")
        print(f"⚠️ 총 {total_missing_test}개의 파일이 원본(test)이 누락되었습니다.")

if __name__ == "__main__":
    find_missing_pairs(TARGET_DIR)