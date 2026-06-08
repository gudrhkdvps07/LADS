#analyzer/sqli_analyzer.py
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional
from .findings import HIGH, MEDIUM, LOW

SLEEP_THRESHOLD      = 4.5
BOOL_GROUP_THRESHOLD = 0.05   # 5% 이상 응답 크기 차이
ORDERBY_DIFF_THRES   = 0.10   # 10% 이상 응답 크기 차이
TIME_CONFIRM_COUNT   = 2      # 최소 2회 재검증

# UNION 오류 패턴
UNION_ERROR_KEYWORDS = (
    "the used select statements have a different number",
    "column count doesn't match",
)

# MySQL 및 공통 DBMS 에러 패턴
DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "duplicate entry",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",
    # 필수 MySQL 에러 패턴
    "mysql_fetch",
    "mysqli_",
    "mariadb server version",
    "sql syntax",
    "mysql error",
    "mysql_num_rows",
    "mysql_query",
    "com.mysql.jdbc.exceptions",
    "org.gjt.mm.mysql",
)

# Boolean TRUE payload 패턴
_BOOL_TRUE = re.compile(
    r"1\s*=\s*1"
    r"|'\s*([a-z0-9])\s*'\s*=\s*'\s*\1"
    r"|\bor\s+1\b"
    r"|\band\s+1\s*=\s*1"
    r"|\btrue\b"
    r"|length\(.+\)\s*>\s*0"
    r"|exists\s*\("
    r"|case\s+when\s*\(\s*1\s*=\s*1",
    re.IGNORECASE,
)

# Boolean FALSE payload 패턴
_BOOL_FALSE = re.compile(
    r"1\s*=\s*2"
    r"|1\s*=\s*0"
    r"|'\s*([a-z0-9])\s*'\s*=\s*'\s*(?!\1)[a-z0-9]\s*'"
    r"|\band\s+1\s*=\s*2"
    r"|\bfalse\b"
    r"|\band\s+0\b"
    r"|case\s+when\s*\(\s*1\s*=\s*2",
    re.IGNORECASE,
)

# ASCII/SUBSTR/REGEXP 등 정찰 payload 패턴
_BOOL_PROBE = re.compile(
    r"ascii\(.+\)\s*[=><]"
    r"|(?:substr|substring|mid)\([^)]+\)\s*[=><]"
    r"|length\(.+\)\s*=\s*\d+"
    r"|.+\s+regexp\s+",
    re.IGNORECASE,
)

_ORDERBY_INJECT = re.compile(r"order\s+by\s+(?:\d+|\(|\w+\s*,)", re.IGNORECASE)
_SLEEP_RE       = re.compile(
    r"sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay",
    re.IGNORECASE,
)


# ─── 헬퍼 ────────────────────────────────────────────────────────

def _is_baseline_result(r: dict) -> bool:
    """baseline(안전한 원본값) 요청인지 확인."""
    meta = r.get("meta") or {}
    return meta.get("is_baseline", False) or meta.get("type") == "BASELINE"


def _is_time_based_payload(payload: str) -> bool:
    return bool(_SLEEP_RE.search(payload or ""))


def _is_group_candidate(payload: str) -> bool:
    if not payload:
        return False
    return bool(
        _BOOL_TRUE.search(payload)
        or _BOOL_FALSE.search(payload)
        or _BOOL_PROBE.search(payload)
        or _ORDERBY_INJECT.search(payload)
    )


def _extract_response(test_result: dict) -> dict:
    if "response" in test_result and isinstance(test_result["response"], dict):
        r = test_result["response"]
        return {
            "body":    (r.get("body") or "").lower(),
            "elapsed": float(r.get("elapsed") or 0.0),
            "length":  int(r.get("length") or 0),
            "status":  r.get("status"),
        }
    body = test_result.get("response_body") or ""
    return {
        "body":    body.lower(),
        "elapsed": float(test_result.get("elapsed") or 0.0),
        "length":  int(test_result.get("length") or 0),
        "status":  test_result.get("status"),
    }


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _body_length(r: dict) -> int:
    if r.get("content_length") is not None:
        return int(r.get("content_length") or 0)
    if isinstance(r.get("response"), dict):
        return int(r["response"].get("length") or 0)
    body = r.get("response_body") or ""
    return len(body)


def _has_db_error(body: str) -> bool:
    if not body:
        return False
    bl = body.lower()
    return any(sig in bl for sig in DB_ERROR_KEYWORDS)


def _check_error_based(body: str) -> Optional[str]:
    bl = body.lower()
    for sig in UNION_ERROR_KEYWORDS:
        if sig in bl:
            return f"UNION-based SQLi (컬럼 수 mismatch: '{sig[:50]}')"
    for sig in DB_ERROR_KEYWORDS:
        if sig in bl:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


# ─── Phase 1: 단건 검증 ──────────────────────────────────────────

def validate_sqli(test_result: dict) -> tuple[bool, str, str]:
    """
    단건 결과 검증. (found, evidence, confidence) 반환.

    Time-based 단건 → Phase 2 그룹 분석으로 위임
    단건 DB 에러 → medium
    confirmed/high는 비교군이 있을 때만
    """
    if not test_result:
        return False, "검증 불가 (입력 없음)", ""

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)", ""

    payload = test_result.get("payload") or ""

    # time-based 단건은 confirmed 금지 → Phase 2로 위임
    if resp["elapsed"] >= SLEEP_THRESHOLD and _is_time_based_payload(payload):
        return False, "time_candidate", ""

    # boolean/probe/orderby → Phase 2 그룹 분석
    if _is_group_candidate(payload):
        return False, "그룹 분석 대상 (Phase 2로 위임)", ""

    # 단건 DB 에러 → medium
    msg = _check_error_based(resp["body"])
    if msg:
        return True, msg, MEDIUM

    return False, "안전함 (SQLi 시그니처 미검출)", ""


# ─── Phase 2: 그룹 분석 ──────────────────────────────────────────

def detect_timebased_group(results: list[dict]) -> list[dict]:
    """
    - baseline 응답 시간 먼저 측정
    - 2회 이상 재검증해야 confirmed/high
    - 단건 지연 → medium/suspected
    """
    sqli_results = [
        r for r in results
        if not r.get("error")
        and not _is_baseline_result(r)
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    time_results = [
        r for r in sqli_results
        if float(r.get("elapsed") or 0) >= SLEEP_THRESHOLD
        and _is_time_based_payload(r.get("payload") or "")
    ]

    if not time_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in time_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    # baseline 결과 수집 (같은 url+param의 안전 응답)
    baseline_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        if _is_baseline_result(r) and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r)):
            key = (r.get("url"), r.get("inject_param"))
            baseline_by_key[key].append(r)

    detected: list[dict] = []

    for key, group in groups.items():
        baseline = baseline_by_key.get(key, [])
        avg_baseline = (
            sum(float(r.get("elapsed") or 0) for r in baseline) / len(baseline)
            if baseline else None
        )
        avg_elapsed = sum(float(r.get("elapsed") or 0) for r in group) / len(group)

        # 2회 이상 → confirmed/high
        if len(group) >= TIME_CONFIRM_COUNT:
            if avg_baseline is not None:
                evidence = (
                    f"Time-based SQLi (confirmed): {len(group)}회 지연 응답 재현 "
                    f"(평균 {avg_elapsed:.2f}s vs baseline {avg_baseline:.2f}s)"
                )
            else:
                evidence = (
                    f"Time-based SQLi (confirmed): {len(group)}회 지연 응답 재현 "
                    f"(평균 {avg_elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
                )
            best = max(group, key=lambda r: float(r.get("elapsed") or 0))
            detected.append({"result": best, "evidence": evidence, "confidence": HIGH})
        else:
            r0 = group[0]
            elapsed = float(r0.get("elapsed") or 0)
            # 단건 → medium/low (confirmed 불가)
            if avg_baseline is not None and avg_baseline < 1.5:
                evidence = (
                    f"Time-based SQLi (suspected): 단일 지연 응답 ({elapsed:.2f}s, "
                    f"baseline {avg_baseline:.2f}s) — 재검증 필요 (REQ-SQLI-015)"
                )
                detected.append({"result": r0, "evidence": evidence, "confidence": MEDIUM})
            else:
                evidence = (
                    f"Time-based SQLi (candidate): 단일 지연 응답 ({elapsed:.2f}s) — "
                    f"baseline 미확인, 재검증 필요"
                )
                detected.append({"result": r0, "evidence": evidence, "confidence": LOW})

    return detected


def detect_boolean_group(results: list[dict]) -> list[dict]:
    """
    - TRUE+FALSE 쌍 필수
    - RUE 응답 ≈ baseline (safe 응답)
    - FALSE 응답 ≠ TRUE 응답 (≥5% 차이)
    - 비교군 없으면 confirmed/high 금지
    """
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and not _is_baseline_result(r)
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    # baseline 수집 (REQ-SQLI-008 비교용)
    baseline_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        if _is_baseline_result(r):
            key = (r.get("url"), r.get("inject_param"))
            baseline_by_key[key].append(r)

    detected: list[dict] = []

    for key, group in groups.items():
        true_items  = [r for r in group if _BOOL_TRUE.search(r.get("payload") or "")]
        false_items = [r for r in group if _BOOL_FALSE.search(r.get("payload") or "")]
        baseline    = baseline_by_key.get(key, [])

        # 1. TRUE+FALSE 쌍 없으면 탈락
        if not (true_items and false_items):
            continue

        # 2. baseline 없으면 탈락
        if not baseline:
            continue

        avg_true     = sum(_body_length(r) for r in true_items)  / len(true_items)
        avg_false    = sum(_body_length(r) for r in false_items) / len(false_items)
        avg_baseline = sum(_body_length(r) for r in baseline)    / len(baseline)

        # 3. TRUE가 baseline과 너무 다르면 탈락 (20% 초과)
        baseline_diff = abs(avg_true - avg_baseline) / max(avg_true, avg_baseline, 1)
        if baseline_diff > 0.20:
            continue

        # 4. FALSE가 baseline과 같으면 탈락 (5% 미만 차이 → 주입 효과 없음)
        false_baseline_diff = abs(avg_false - avg_baseline) / max(avg_false, avg_baseline, 1)
        if false_baseline_diff < BOOL_GROUP_THRESHOLD:
            continue

        # 5. TRUE랑 FALSE가 비슷하면 탈락 (5% 미만 차이)
        max_len = max(avg_true, avg_false, 1)
        diff    = abs(avg_true - avg_false) / max_len
        if diff < BOOL_GROUP_THRESHOLD:
            continue

        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"Boolean-based SQLi (confirmed): "
            f"true={avg_true:.0f}b ≈ baseline={avg_baseline:.0f}b, "
            f"false={avg_false:.0f}b, diff={diff:.1%} ({direction})"
        )
        best = max(true_items, key=_body_length)
        detected.append({"result": best, "evidence": evidence, "confidence": HIGH})

    return detected


def detect_probe_group(results: list[dict]) -> list[dict]:
    """ASCII/SUBSTRING/MID/REGEXP/LENGTH=N 정찰 페이로드 그룹 탐지."""
    probe_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and not _is_baseline_result(r)
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
        and _BOOL_PROBE.search(r.get("payload") or "")
    ]

    if not probe_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in probe_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        lengths = [_body_length(r) for r in group]
        if not lengths:
            continue

        min_len    = min(lengths)
        max_len_v  = max(lengths)
        diff       = (max_len_v - min_len) / max(max_len_v, 1)
        sample_body = (group[0].get("response_body") or "").lower()
        has_error   = _has_db_error(sample_body)

        if diff >= BOOL_GROUP_THRESHOLD and len(group) >= 2:
            evidence   = (
                f"Boolean Probe SQLi (confirmed): {len(group)}개 정찰 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%})"
            )
            confidence = MEDIUM
        elif has_error:
            evidence   = (
                f"Boolean Probe SQLi (suspected): {len(group)}개 정찰 페이로드, "
                f"응답 동일하지만 DB 에러 동반"
            )
            confidence = MEDIUM
        else:
            evidence   = (
                f"Boolean Probe SQLi candidate: {len(group)}개 정찰 페이로드 "
                f"(ASCII/SUBSTRING/MID/REGEXP), 응답 차이 없음"
            )
            confidence = LOW

        best = max(group, key=_body_length)
        detected.append({"result": best, "evidence": evidence, "confidence": confidence})

    return detected


def detect_orderby_group(results: list[dict]) -> list[dict]:
    """
    - 정상 index + 비정상 index 쌍 비교 필수
    - 정상 ORDER BY ≈ baseline
    - 비정상 ORDER BY → SQL 에러 또는 응답 차이
    """
    orderby_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and not _is_baseline_result(r)
        and _ORDERBY_INJECT.search(r.get("payload") or "")
    ]

    if not orderby_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in orderby_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    baseline_by_key: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        if _is_baseline_result(r):
            key = (r.get("url"), r.get("inject_param"))
            baseline_by_key[key].append(r)

    detected: list[dict] = []

    for key, group in groups.items():
        baseline = baseline_by_key.get(key, [])

        if len(group) < 2:
            sample_body = (group[0].get("response_body") or "").lower()
            error_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""

            if baseline:
                avg_baseline = sum(_body_length(r) for r in baseline) / len(baseline)
                single_len = _body_length(group[0])
                diff = abs(single_len - avg_baseline) / max(single_len, avg_baseline, 1)
                if diff >= ORDERBY_DIFF_THRES:
                    evidence = (
                        f"ORDER BY SQLi (suspected): 단일 페이로드 vs baseline 차이 "
                        f"({single_len}b vs {avg_baseline:.0f}b, diff={diff:.1%}){error_note}"
                    )
                    detected.append({"result": group[0], "evidence": evidence, "confidence": MEDIUM})
                else:
                    evidence = (
                        f"ORDER BY SQLi candidate: 단일 페이로드, baseline 차이 미미 "
                        f"(diff={diff:.1%}){error_note}"
                    )
                    detected.append({"result": group[0], "evidence": evidence, "confidence": LOW})
            else:
                evidence = (
                    f"ORDER BY SQLi candidate: 단일 페이로드, "
                    f"비교용 쌍 없음{error_note}"
                )
                detected.append({"result": group[0], "evidence": evidence, "confidence": LOW})
            continue

        lengths   = [_body_length(r) for r in group]
        min_len   = min(lengths)
        max_len_v = max(lengths)
        if max_len_v == 0:
            continue

        diff = (max_len_v - min_len) / max_len_v

        has_error = any(
            "unknown column" in (r.get("response_body") or "").lower()
            for r in group
        )

        if diff >= ORDERBY_DIFF_THRES or has_error:
            extra = " + 'unknown column' 에러" if has_error else ""
            evidence = (
                f"ORDER BY SQLi (confirmed): {len(group)}개 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%}){extra}"
            )
            best = max(group, key=_body_length)
            detected.append({"result": best, "evidence": evidence, "confidence": HIGH})
        else:
            sample_body = (group[0].get("response_body") or "").lower()
            db_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
            evidence = (
                f"ORDER BY SQLi candidate: {len(group)}개 페이로드, "
                f"응답 동일 (diff={diff:.1%}){db_note}"
            )
            detected.append({"result": group[0], "evidence": evidence, "confidence": LOW})

    return detected

