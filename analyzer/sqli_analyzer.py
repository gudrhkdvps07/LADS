from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

SLEEP_THRESHOLD       = 4.5
BOOL_SIGNAL_MIN       = 0.05
BOOL_GROUP_THRESHOLD  = 0.05
ORDERBY_DIFF_THRES    = 0.10

UNION_ERROR_KEYWORDS = (
    "the used select statements have a different number",
    "column count doesn't match",
)

DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",
)

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
_BOOL_FALSE = re.compile(
    r"1\s*=\s*2"
    r"|1\s*=\s*0"
    r"|\band\s+1\s*=\s*2"
    r"|\bfalse\b"
    r"|\band\s+0\b"
    r"|case\s+when\s*\(\s*1\s*=\s*2",
    re.IGNORECASE,
)

_BOOL_PROBE = re.compile(
    r"ascii\(.+\)\s*[=><]"
    r"|(?:substr|substring|mid)\([^)]+\)\s*[=><]"
    r"|length\(.+\)\s*=\s*\d+"
    r"|.+\s+regexp\s+",
    re.IGNORECASE,
)

_ORDERBY_INJECT = re.compile(r"order\s+by\s+(?:\d+|\(|\w+\s*,)", re.IGNORECASE)
_ORDERBY_NUM = re.compile(r"order\s+by\s+(\d+)", re.IGNORECASE)


def _is_group_candidate(payload: str) -> bool:
    if not payload:
        return False
    if _BOOL_TRUE.search(payload):
        return True
    if _BOOL_FALSE.search(payload):
        return True
    if _BOOL_PROBE.search(payload):
        return True
    if _ORDERBY_INJECT.search(payload):
        return True
    return False


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
    return r.get("content_length") or 0


def _has_db_error(body: str) -> bool:
    if not body:
        return False
    return any(sig in body for sig in DB_ERROR_KEYWORDS)


def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None


def _check_error_based(body: str) -> Optional[str]:
    for sig in UNION_ERROR_KEYWORDS:
        if sig in body:
            return f"UNION-based SQLi (컬럼 수 mismatch: '{sig[:50]}')"
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


def validate_sqli(test_result: dict) -> tuple[bool, str]:
    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    msg = _check_time_based(resp["elapsed"])
    if msg:
        return True, msg

    payload = test_result.get("payload") or ""
    if _is_group_candidate(payload):
        return False, "그룹 분석 대상 (Phase 2로 위임)"

    msg = _check_error_based(resp["body"])
    if msg:
        return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"


def detect_boolean_group(results: list[dict]) -> list[dict]:
    """
    판정 단계:
      [confirmed] TRUE+FALSE 짝 있고 응답 차이 >= 5%
      [suspected] TRUE+FALSE 짝 있고 응답 동일 + DB 에러 시그니처 동반
      [candidate] TRUE+FALSE 짝 있지만 응답 동일, DB 에러 없음
      [candidate] TRUE 또는 FALSE 한쪽만 있음
    """
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        true_items, false_items = [], []
        for r in group:
            payload = r.get("payload") or ""
            if _BOOL_TRUE.search(payload):
                true_items.append(r)
            if _BOOL_FALSE.search(payload):
                false_items.append(r)

        if true_items and false_items:
            avg_true  = sum(_body_length(r) for r in true_items)  / len(true_items)
            avg_false = sum(_body_length(r) for r in false_items) / len(false_items)
            max_len   = max(avg_true, avg_false, 1)
            diff      = abs(avg_true - avg_false) / max_len

            if diff >= BOOL_GROUP_THRESHOLD:
                direction = "true>false" if avg_true > avg_false else "true<false"
                evidence = (
                    f"Boolean-based SQLi (confirmed): "
                    f"true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
                    f"diff={diff:.1%} ({direction})"
                )
                best = max(true_items, key=_body_length)
                detected.append({"result": best, "evidence": evidence})
                continue

            sample_body = (true_items[0].get("response_body") or "").lower()
            if _has_db_error(sample_body):
                evidence = (
                    f"Boolean-based SQLi (suspected): "
                    f"true {len(true_items)}개 / false {len(false_items)}개 시도, "
                    f"응답 크기 동일 (diff={diff:.1%}) + DB 에러 시그니처 동반 → "
                    f"CMS 동일 에러 페이지 환경 (그누보드 등)"
                )
            else:
                evidence = (
                    f"Boolean SQLi candidate: "
                    f"true {len(true_items)}개 / false {len(false_items)}개 시도, "
                    f"응답 동일 (diff={diff:.1%}), 수동 확인 필요"
                )
            best = true_items[0]
            detected.append({"result": best, "evidence": evidence})
            continue

        candidate_items = true_items or false_items
        if candidate_items:
            kind = "TRUE" if true_items else "FALSE"
            sample_body = (candidate_items[0].get("response_body") or "").lower()
            error_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
            evidence = (
                f"Boolean SQLi candidate ({kind} only): "
                f"{len(candidate_items)}개 페이로드 시도, "
                f"짝 페이로드 부재로 응답 비교 불가{error_note}"
            )
            best = candidate_items[0]
            detected.append({"result": best, "evidence": evidence})

    return detected


def detect_probe_group(results: list[dict]) -> list[dict]:
    """ASCII/SUBSTRING/MID/REGEXP/LENGTH=N 등 정찰 페이로드 전용."""
    probe_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
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

        min_len, max_len_v = min(lengths), max(lengths)
        diff = (max_len_v - min_len) / max(max_len_v, 1)

        sample_body = (group[0].get("response_body") or "").lower()
        has_error = _has_db_error(sample_body)

        if diff >= BOOL_GROUP_THRESHOLD and len(group) >= 2:
            evidence = (
                f"Boolean Probe SQLi (confirmed): {len(group)}개 정찰 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%})"
            )
        elif has_error:
            evidence = (
                f"Boolean Probe SQLi (suspected): {len(group)}개 정찰 페이로드 시도, "
                f"응답 동일하지만 DB 에러 시그니처 동반"
            )
        else:
            evidence = (
                f"Boolean Probe SQLi candidate: {len(group)}개 정찰 페이로드 시도 "
                f"(ASCII/SUBSTRING/MID/REGEXP 등), 응답 차이 없음"
            )

        best = max(group, key=_body_length)
        detected.append({"result": best, "evidence": evidence})

    return detected


def detect_orderby_group(results: list[dict]) -> list[dict]:
    orderby_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and _ORDERBY_INJECT.search(r.get("payload") or "")
    ]

    if not orderby_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in orderby_results:
        key = (r.get("url"), r.get("inject_param"))
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        if len(group) < 2:
            if group:
                sample_body = (group[0].get("response_body") or "").lower()
                error_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
                evidence = (
                    f"ORDER BY SQLi candidate: 단일 페이로드 시도, "
                    f"비교용 baseline 부족{error_note}"
                )
                detected.append({"result": group[0], "evidence": evidence})
            continue

        lengths = [_body_length(r) for r in group]
        min_len, max_len_v = min(lengths), max(lengths)
        if max_len_v == 0:
            continue

        diff = (max_len_v - min_len) / max_len_v

        has_error = any(
            "unknown column" in (r.get("response_body") or "").lower()
            for r in group
        )

        if diff >= ORDERBY_DIFF_THRES or has_error:
            evidence_extra = " + 'unknown column' 에러" if has_error else ""
            evidence = (
                f"ORDER BY SQLi (confirmed): {len(group)}개 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%}){evidence_extra}"
            )
            best = max(group, key=_body_length)
            detected.append({"result": best, "evidence": evidence})
        else:
            sample_body = (group[0].get("response_body") or "").lower()
            db_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
            evidence = (
                f"ORDER BY SQLi candidate: {len(group)}개 페이로드 시도, "
                f"응답 동일 (diff={diff:.1%}){db_note}"
            )
            best = group[0]
            detected.append({"result": best, "evidence": evidence})

    return detected