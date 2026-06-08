from __future__ import annotations

from .sqli_analyzer import (
    validate_sqli,
    detect_boolean_group,
    detect_orderby_group,
    detect_probe_group,
    detect_timebased_group,
)
from .xss_analyzer  import validate_xss
from utilities import load_json, save_json
from analyzer.findings import (
    make_finding,
    MODULE_XSS, MODULE_SQLI,
    XSS_CONFIRMED, SQLI_CONFIRMED,
    HIGH, MEDIUM, LOW,
)

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss",
    "detect_boolean_group", "detect_orderby_group",
    "detect_probe_group", "detect_timebased_group",
]


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _derive_module_type(vt: str) -> tuple[str, str]:
    if "xss" in vt:
        return MODULE_XSS, XSS_CONFIRMED
    if "sqli" in vt or "sql" in vt:
        return MODULE_SQLI, SQLI_CONFIRMED
    return MODULE_XSS, XSS_CONFIRMED


def _derive_category(vt: str, evidence: str) -> str:
    # XSS는 evidence/payload 문자열에 의한 오분류 방지를 위해 먼저 처리
    if "xss" in vt:
        return "reflected"
    # SQLi 전용 category 추론
    ev = evidence.lower()
    if "time" in ev:
        return "time_based"
    if "error" in ev or "db 에러" in ev or "union" in ev:
        return "error_based"
    if "boolean" in ev:
        return "boolean"
    if "order by" in ev or "orderby" in ev:
        return "order_by"
    if "probe" in ev:
        return "boolean_probe"
    return "unknown"


def _make_finding(r: dict, evidence: str, confidence: str = LOW) -> dict:
    meta     = r.get("meta") or {}
    vt       = (meta.get("vuln_type") or "").lower()
    module, type_ = _derive_module_type(vt)
    category      = _derive_category(vt, evidence)

    f = make_finding(
        module=module,
        type=type_,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=confidence,
        evidence=evidence,
    )
    f["id"]          = r.get("id")
    f["point"]       = r.get("point")
    f["inject_mode"] = r.get("inject_mode")
    f["elapsed"]     = r.get("elapsed") or 0.0
    f["role"]        = meta.get("role")
    return f


def _validate_single(r: dict) -> tuple[bool, str, str]:
    """단건 검증. (found, evidence, confidence) 반환."""
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)

    ok, ev, conf = validate_xss(r)
    if ok:
        return True, ev, conf
    return validate_sqli(r)


def validate(
    results: list[dict],
    progress_callback=None,
) -> list[dict]:
    findings:  list[dict] = []
    found_ids: set        = set()
    total = len(results)

    # ── Phase 1: 단건 검증 ────────────────────────────────────────
    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)
        if r.get("error") or not r.get("response_body"):
            continue
        ok, evidence, confidence = _validate_single(r)
        if ok and evidence:
            findings.append(_make_finding(r, evidence, confidence))
            found_ids.add(r.get("id"))

    # ── Phase 2: 그룹 분석 ────────────────────────────────────────

    # REQ-SQLI-014~016: Time-based 그룹 (다중 재현 필요)
    for item in detect_timebased_group(results):
        r        = item["result"]
        evidence = item["evidence"]
        conf     = item.get("confidence", MEDIUM)
        if r.get("id") in found_ids:
            continue
        findings.append(_make_finding(r, evidence, conf))
        found_ids.add(r.get("id"))

    # REQ-SQLI-007~010: Boolean / Probe / ORDER BY 그룹
    for detector in [detect_boolean_group]:
        for item in detector(results):
            r        = item["result"]
            evidence = item["evidence"]
            conf     = item.get("confidence", MEDIUM)
            if r.get("id") in found_ids:
                continue
            if "diff=0.0%" in (evidence or ""):
                continue
            findings.append(_make_finding(r, evidence, conf))
            found_ids.add(r.get("id"))

    return findings


def run(
    input_file:  str = "results/execution_results.json",
    output_file: str = "results/findings.json",
    progress_callback=None,
) -> list[dict]:
    results  = load_json(input_file, [])
    findings = validate(results, progress_callback=progress_callback)
    save_json(output_file, findings)
    return findings
