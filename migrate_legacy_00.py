"""
migrate_legacy_00.py
selected_legacy_tests.csv 기반으로 00_legacy_db_derived 파일을
01_regression / 02_semantic_generalization / 03_structural_generalization 으로 이동.

사용법:
    python migrate_legacy_00.py           # 실제 이동
    python migrate_legacy_00.py --dry-run # 미리보기만 (파일 수정 없음)

cleanup_note가 있는 11개 파일은 이동 후 수동 확인 목록 출력.
"""
import os, csv, shutil, ast, argparse

BASE_DIR   = "py_dataset"
LEGACY_DIR = os.path.join(BASE_DIR, "00_legacy_db_derived")
CSV_PATH   = "selected_legacy_tests.csv"

def load_plan(csv_path):
    with open(csv_path, encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))

def run(dry_run=False):
    rows = load_plan(CSV_PATH)
    print(f"{'[DRY RUN] ' if dry_run else ''}이동 대상: {len(rows)}개\n")

    moved = skipped = errors = 0
    needs_cleanup = []

    for r in rows:
        src_name   = r['legacy_file']
        dst_rel    = r['target_path']          # 예: 02_semantic_generalization/CWE-1004_13_test.py
        cleanup    = r['cleanup_note'].strip()

        src_path = os.path.join(LEGACY_DIR, src_name)
        dst_path = os.path.join(BASE_DIR, dst_rel)
        dst_dir  = os.path.dirname(dst_path)

        # 소스 파일 존재 확인
        if not os.path.exists(src_path):
            print(f"  ⚠️  소스 없음: {src_name}")
            skipped += 1
            continue

        # 목적지 파일 중복 확인
        if os.path.exists(dst_path):
            print(f"  ⚠️  이미 존재: {dst_rel} (건너뜀)")
            skipped += 1
            continue

        # 문법 검증
        try:
            ast.parse(open(src_path, encoding='utf-8').read())
        except SyntaxError as e:
            print(f"  ❌ 문법 오류: {src_name}: {e}")
            errors += 1
            continue

        if dry_run:
            print(f"  → {src_name:<40} {dst_rel}")
            if cleanup:
                print(f"     ⚠️  cleanup 필요: {cleanup}")
        else:
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copy2(src_path, dst_path)
            print(f"  ✅ {src_name:<40} → {dst_rel}")

        moved += 1
        if cleanup:
            needs_cleanup.append((src_name, dst_path, cleanup))

    print(f"\n{'[DRY RUN] ' if dry_run else ''}완료: {moved}개 이동, {skipped}개 건너뜀, {errors}개 오류")

    if needs_cleanup:
        print(f"\n⚠️  cleanup_note 있는 파일 {len(needs_cleanup)}개 — 이동 후 수동 확인 필요:")
        print("-" * 60)
        for src, dst, note in needs_cleanup:
            print(f"  파일: {os.path.basename(dst)}")
            print(f"  위치: {dst}")
            print(f"  작업: {note}")
            print()

    return moved, skipped, errors

def run_patches(dry_run=False):
    rows = load_plan(CSV_PATH)
    print(f"{'[DRY RUN] ' if dry_run else ''}Patch 이동 대상: {len(rows)}개\n")

    moved = skipped = errors = 0

    for r in rows:
        # test 파일 이름을 기반으로 patch 파일 이름을 유추합니다.
        src_name   = r['legacy_file'].replace('test.py', 'patch.py')
        dst_rel    = r['target_path'].replace('test.py', 'patch.py')

        src_path = os.path.join(LEGACY_DIR, src_name)
        dst_path = os.path.join(BASE_DIR, dst_rel)
        dst_dir  = os.path.dirname(dst_path)

        # 소스 파일 존재 확인
        if not os.path.exists(src_path):
            print(f"  ⚠️  Patch 소스 없음: {src_name}")
            skipped += 1
            continue

        # 목적지 파일 중복 확인
        if os.path.exists(dst_path):
            print(f"  ⚠️  Patch 이미 존재: {dst_rel} (건너뜀)")
            skipped += 1
            continue

        # 문법 검증
        try:
            ast.parse(open(src_path, encoding='utf-8').read())
        except SyntaxError as e:
            print(f"  ❌ Patch 문법 오류: {src_name}: {e}")
            errors += 1
            continue

        if dry_run:
            print(f"  → {src_name:<40} {dst_rel}")
        else:
            os.makedirs(dst_dir, exist_ok=True)
            shutil.copy2(src_path, dst_path)
            print(f"  ✅ {src_name:<40} → {dst_rel}")

        moved += 1

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Patch 완료: {moved}개 이동, {skipped}개 건너뜀, {errors}개 오류")
    return moved, skipped, errors

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true', help='미리보기만 (파일 수정 없음)')
    ap.add_argument('--patch-only', action='store_true', help='patch 파일만 이동')
    ap.add_argument('--all', action='store_true', help='test + patch 모두 이동')
    args = ap.parse_args()

    if args.patch_only:
        run_patches(dry_run=args.dry_run)
    elif args.all:
        run(dry_run=args.dry_run)
        run_patches(dry_run=args.dry_run)
    else:
        run(dry_run=args.dry_run)