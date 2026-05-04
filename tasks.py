import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

BASE_URL           = os.getenv("TARGET_URL",         "http://localhost:8080")
CRAWL_RESULT_FILE  = os.getenv("CRAWL_RESULT",       "crawl_result.json")
TARGETS_FILE       = os.getenv("TARGETS_FILE",        "targets.json")
PAYLOADS_FILE      = os.getenv("PAYLOADS_FILE",       "results/payloads_llm.json")
SCAN_RESULTS_FILE  = os.getenv("SCAN_RESULTS_FILE",   "results/scan_results_llm.json")
PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE",  "results/payloads_llm_meta.json")
FUZZ_TASKS_FILE    = os.getenv("FUZZ_TASKS_FILE",     "fuzz_tasks.json")
EXEC_RESULTS_FILE  = os.getenv("EXEC_RESULTS_FILE",   "execution_results.json")
FINDINGS_FILE      = os.getenv("FINDINGS_FILE",       "results/findings.json")


def _task_crawl():
    from crawler import Crawler
    from target_builder import build_targets, print_summary

    print(f"크롤링 시작: {BASE_URL}")
    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save(CRAWL_RESULT_FILE)
    crawler.summary()

    print(f"타겟 구성 시작: {CRAWL_RESULT_FILE}")
    with open(CRAWL_RESULT_FILE, encoding="utf-8") as f:
        pages = json.load(f)
    targets = build_targets(pages)

    os.makedirs("results", exist_ok=True)
    with open(TARGETS_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"타겟 구성 완료: {TARGETS_FILE} ({len(targets)}개)")
    print_summary(targets)


def _task_payload():
    from payload.generate_payloads import run as generate_run

    os.makedirs("results", exist_ok=True)
    print(f"LLM 페이로드 생성 시작 (출력: {PAYLOADS_FILE})")
    generate_run(out_file=PAYLOADS_FILE)


def _task_scan():
    import scanner

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음. 페이로드를 먼저 생성하세요.")
        return

    os.makedirs("results", exist_ok=True)

    old_argv = sys.argv[:]
    argv_list = ["scanner.py", "--payloads", PAYLOADS_FILE, "--out", SCAN_RESULTS_FILE]
    if os.path.exists(TARGETS_FILE):
        argv_list += ["--targets", TARGETS_FILE]

    sys.argv = argv_list
    try:
        scanner.main()
    except SystemExit as e:
        if e.code and e.code != 0:
            print(f"[ERROR] 스캐너 종료: exit code {e.code}")
    finally:
        sys.argv = old_argv


def _task_fuzz():
    from fuzzer.fuzzing_strategy import build_tasks

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음.")
        print(f"        페이로드 생성(② LLM 페이로드 생성)을 먼저 실행하세요.")
        return

    if not os.path.exists(PAYLOADS_META_FILE):
        print(f"[WARN] {PAYLOADS_META_FILE} 없음.")
        return

    with open(PAYLOADS_META_FILE, encoding="utf-8") as f:
        points_meta = json.load(f)

    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        payloads = json.load(f)

    targets = None
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, encoding="utf-8") as f:
            targets = json.load(f)

    print(f"meta={len(points_meta)} payload_points={len(payloads)}")
    tasks = build_tasks(points_meta, payloads, targets)

    with open(FUZZ_TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

    replace_ = sum(1 for t in tasks if t.get("inject_mode") == "replace")
    append_  = sum(1 for t in tasks if t.get("inject_mode") == "append")
    print(f"완료: {len(tasks)} 태스크 → {FUZZ_TASKS_FILE}")
    print(f"         mode  → replace: {replace_}, append: {append_}")


def _task_execute():
    from fuzzer.executor import execute

    if not os.path.exists(FUZZ_TASKS_FILE):
        print(f"[ERROR] {FUZZ_TASKS_FILE} 없음. 전략 수립을 먼저 실행하세요.")
        return

    with open(FUZZ_TASKS_FILE, encoding="utf-8") as f:
        tasks = json.load(f)

    print(f"{len(tasks)} 태스크 실행 시작")
    results = execute(tasks, timeout=10, delay=0.0, output_file=EXEC_RESULTS_FILE)

    ok      = sum(1 for r in results if r["error"] is None)
    timeout = sum(1 for r in results if r["error"] == "timeout")
    err     = sum(1 for r in results if r["error"] and r["error"] != "timeout")
    print(f"완료: 성공 {ok} / 타임아웃 {timeout} / 오류 {err} → {EXEC_RESULTS_FILE}")


def _task_validate():
    from fuzzer.validator import run as validate_run

    if not os.path.exists(EXEC_RESULTS_FILE):
        print(f"[ERROR] {EXEC_RESULTS_FILE} 없음. 실행을 먼저 하세요.")
        return

    print(f"[Validator] {EXEC_RESULTS_FILE} 분석 중...")
    findings = validate_run(input_file=EXEC_RESULTS_FILE, output_file=FINDINGS_FILE)

    xss_cnt  = sum(1 for f in findings if "xss"  in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower()
                                       or "sql"  in (f.get("vuln_type") or "").lower())

    print(f"[Validator] 완료: 취약점 {len(findings)}개 발견 → {FINDINGS_FILE}")
    print(f"           XSS: {xss_cnt}개  /  SQLi: {sqli_cnt}개")
    for f in findings:
        print(f"  [{f['vuln_type']:20s}] {f['point']} | {f['payload'][:50]} | {f['evidence']}")


def _task_all(skip_crawl: bool = False, skip_payload: bool = False):
    if skip_crawl:
        print(f"[건너뜀] 크롤링 — {CRAWL_RESULT_FILE} 재사용")
    else:
        _task_crawl()

    if skip_payload:
        print(f"[건너뜀] 페이로드 생성 — {PAYLOADS_FILE} 재사용")
    else:
        _task_payload()

    _task_scan()


def reload_config():
    """설정 저장 후 환경변수 갱신 — app.py /config POST에서 호출"""
    global BASE_URL, CRAWL_RESULT_FILE, TARGETS_FILE, PAYLOADS_FILE
    global SCAN_RESULTS_FILE, PAYLOADS_META_FILE, FUZZ_TASKS_FILE
    global EXEC_RESULTS_FILE, FINDINGS_FILE
    load_dotenv(override=True)
    BASE_URL           = os.getenv("TARGET_URL",         "http://34.68.27.120:8081")
    CRAWL_RESULT_FILE  = os.getenv("CRAWL_RESULT",       "crawl_result.json")
    TARGETS_FILE       = os.getenv("TARGETS_FILE",        "targets.json")
    PAYLOADS_FILE      = os.getenv("PAYLOADS_FILE",       "results/payloads_llm.json")
    SCAN_RESULTS_FILE  = os.getenv("SCAN_RESULTS_FILE",   "results/scan_results_llm.json")
    PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE",  "results/payloads_llm_meta.json")
    FUZZ_TASKS_FILE    = os.getenv("FUZZ_TASKS_FILE",     "fuzz_tasks.json")
    EXEC_RESULTS_FILE  = os.getenv("EXEC_RESULTS_FILE",   "execution_results.json")
    FINDINGS_FILE      = os.getenv("FINDINGS_FILE",       "results/findings.json")


TASK_FUNCS = {
    "crawl"   : _task_crawl,
    "payload" : _task_payload,
    "scan"    : _task_scan,
    "fuzz"    : _task_fuzz,
    "execute" : _task_execute,
    "validate": _task_validate,
    "all"     : _task_all,
}

TASK_LABELS = {
    "crawl"   : "크롤링 + 타겟 구성",
    "payload" : "LLM 페이로드 생성",
    "scan"    : "스캔 실행",
    "fuzz"    : "퍼징 · 전략 수립",
    "execute" : "퍼징 · 실행",
    "validate": "퍼징 · 취약점 판정",
    "all"     : "전체 파이프라인",
}
