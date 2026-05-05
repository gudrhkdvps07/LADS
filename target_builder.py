import json
import re
import sys
import os
from urllib.parse import urlparse

INPUT_FILE  = os.getenv("CRAWL_RESULT",  "results/crawl_result.json")
OUTPUT_FILE = os.getenv("TARGETS_FILE",  "results/targets.json")

# CSRF/토큰/캡차 계열 필드는 공격 대상에서 제외
CSRF_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

# 버튼/파일 계열 input은 공격 대상에서 제외
SKIP_TYPES = {"submit", "button", "reset", "image", "file"}



# ----- 헬퍼 함수 -----

# 이 파라미터에 공격 넣을지 판단
def _injectable(name: str, field_type: str) -> bool:
    if not name:
        return False
    if field_type in SKIP_TYPES:
        return False
    if CSRF_RE.search(name):
        return False
    return True

# 쿼리 제거
def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()

# 중복 제거를 위한 시그니처 생성 헬퍼
def _form_sig(action: str, method: str, enctype: str, names: list[str]) -> str:
    method = (method or "GET").upper()
    action = (action or "").strip()
    enctype = (enctype or "application/x-www-form-urlencoded").lower()
    return f"{method}:{action}:{enctype}:{','.join(sorted(names))}"

def _url_sig(base: str, names: list[str]) -> str:
    base = (base or "").strip()
    return f"GET:{base}:{','.join(sorted(names))}"




def build_targets(pages: list[dict]) -> list[dict]:
    targets: list[dict] = []
    seen: set[str] = set()
    tid = 0

    for page in pages:
        source = page.get("url", "").strip()
        if not source:
            continue

        # 1. URL 쿼리 파라미터
        qp = page.get("query_params", {})
        if qp:
            base = _base_url(source)
            params = []

            for name, vals in qp.items():
                name = (name or "").strip()
                if not name:
                    continue

                field_type = "url_param"

                params.append({
                    "name": name,
                    "field_type": field_type,
                    "default_value": vals[0] if vals else "",
                    "options": [],
                    "injectable": _injectable(name, field_type),
                })

            if params:
                sig = _url_sig(base, [p["name"] for p in params])

                if sig not in seen:
                    seen.add(sig)
                    tid += 1
                    targets.append({
                        "id": f"url_{tid:04d}",
                        "type": "url_param",
                        "source_url": source,
                        "action": base,
                        "method": "GET",
                        "enctype": "application/x-www-form-urlencoded",
                        "params": params,
                    })

        # 2. HTML Form
        for form in page.get("forms", []):
            action = form.get("action", "").strip()
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded").lower()

            if not action:
                continue

            params = []

            for f in form.get("fields", []):
                name = (f.get("name") or "").strip()
                field_type = (f.get("field_type") or "text").lower()

                if not name:
                    continue

                if field_type in SKIP_TYPES:
                    continue

                params.append({
                    "name": name,
                    "field_type": field_type,
                    "default_value": f.get("value", ""),
                    "options": f.get("options", []),
                    "injectable": _injectable(name, field_type),
                })

            if not params:
                continue

            sig = _form_sig(action, method, enctype, [p["name"] for p in params])

            if sig not in seen:
                seen.add(sig)
                tid += 1
                targets.append({
                    "id": f"form_{tid:04d}",
                    "type": "form",
                    "source_url": source,
                    "action": action,
                    "method": method,
                    "enctype": enctype,
                    "params": params,
                })

    return targets


# 요약 출력
def print_summary(targets: list[dict]) -> None:
    url_t = [t for t in targets if t["type"] == "url_param"]
    form_t = [t for t in targets if t["type"] == "form"]
    post_t = [t for t in form_t if t["method"] == "POST"]
    get_t = [t for t in form_t if t["method"] == "GET"]

    total_injectable = sum(
        sum(1 for p in t["params"] if p["injectable"])
        for t in targets
    )

    sep = "=" * 60
    print(f"\n{sep}")
    print("공격 표면 분석 결과")
    print(sep)
    print(f"총 타겟                : {len(targets)}")
    print(f"  URL 파라미터 타겟    : {len(url_t)}")
    print(f"  Form 타겟            : {len(form_t)}")
    print(f"    POST form          : {len(post_t)}")
    print(f"    GET form           : {len(get_t)}")
    print(f"주입 가능 파라미터 합계: {total_injectable}")
    print()

    for t in targets:
        inj = [p["name"] for p in t["params"] if p["injectable"]]
        skip = [p["name"] for p in t["params"] if not p["injectable"]]

        print(f"  [{t['id']}] {t['method']} {t['action']}")

        if inj:
            print(f"           inject : {inj}")
        if skip:
            print(f"           skip   : {skip}")


if __name__ == "__main__":
    try:
        with open(INPUT_FILE, encoding="utf-8") as f:
            pages = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] {INPUT_FILE} 없음 — 먼저 crawler.py를 실행하세요.", file=sys.stderr)
        sys.exit(1)

    targets = build_targets(pages)

    parent = os.path.dirname(OUTPUT_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"저장 완료: {OUTPUT_FILE}  ({len(targets)}개 타겟)")
    print_summary(targets)
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
