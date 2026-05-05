"""
Step 8.5 - Validator
executor 결과(execution_results.json) -> 취약 판정 -> findings 저장
scanner.py의 detect/has_xss_marker/has_mysql_error 로직 기반
"""
from __future__ import annotations

import json

# scanner.py에서 추출한 탐지 패턴
_MYSQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "column count doesn't match",
    "the used select statements have a different number",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",
]

_XSS_MARKERS = [
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    "onerror=prompt",
]


def _check_xss(body: str) -> tuple[bool, str]:
    tl = body.lower()
    for marker in _XSS_MARKERS:
        ml = marker.lower()
        idx = tl.find(ml)
        if idx == -1:
            continue
        surrounding = body[max(0, idx - 10): idx + len(marker) + 10]
        # HTML 인코딩됐으면 무효
        if "&lt;" in surrounding or "&gt;" in surrounding or "&quot;" in surrounding:
            continue
        return True, f"xss_reflected: '{marker}'"
    return False, ""


def _check_sqli(body: str) -> tuple[bool, str]:
    tl = body.lower()
    for pattern in _MYSQL_ERRORS:
        if pattern in tl:
            return True, f"mysql_error: '{pattern}'"
    return False, ""


def _check_time(elapsed: float, threshold: float = 4.5) -> tuple[bool, str]:
    if elapsed >= threshold:
        return True, f"time_delay={elapsed:.2f}s (>= {threshold}s)"
    return False, ""


def validate(results: list[dict]) -> list[dict]:
    """executor 결과 리스트 -> 취약 판정 findings 리스트"""
    findings = []

    for r in results:
        if r.get("error") or not r.get("response_body"):
            continue

        body = r["response_body"]
        meta = r.get("meta") or {}
        vuln_type = (meta.get("vuln_type") or "").lower()
        elapsed = r.get("elapsed") or 0.0

        found = False
        evidence = ""

        if "xss" in vuln_type:
            found, evidence = _check_xss(body)
        elif "sqli" in vuln_type or "sql" in vuln_type:
            # Error-based 먼저
            found, evidence = _check_sqli(body)
            # Time-based fallback
            if not found and "time" in vuln_type:
                found, evidence = _check_time(elapsed)
        else:
            # 타입 불명확하면 둘 다 시도
            found, evidence = _check_xss(body)
            if not found:
                found, evidence = _check_sqli(body)

        if found:
            findings.append({
                "id":             r.get("id"),
                "point":          r.get("point"),
                "url":            r.get("url"),
                "method":         r.get("method"),
                "param":          r.get("inject_param"),
                "payload":        r.get("payload"),
                "inject_mode":    r.get("inject_mode"),
                "vuln_type":      meta.get("vuln_type"),
                "status":         r.get("status"),
                "elapsed":        elapsed,
                "evidence":       evidence,
            })

    return findings


def run(
    input_file: str = "results/execution_results.json",
    output_file: str = "results/findings.json",
) -> list[dict]:
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = validate(results)

    import os
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings
