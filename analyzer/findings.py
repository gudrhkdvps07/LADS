"""
findings.py - 공통 findings 스키마 정의
"""

from __future__ import annotations
from typing import Optional
import json
import os

# findings 저장 경로
FINDINGS_FILE = os.getenv("FINDINGS_FILE", "results/findings.json")

# ── type 상수 ──────────────────────────────────────────────
# SQLi
SQLI_CONFIRMED       = "SQLI_CONFIRMED"

# XSS
XSS_CONFIRMED        = "XSS_CONFIRMED"

# ── confidence 상수 ────────────────────────────────────────
HIGH   = "high"
MEDIUM = "medium"
LOW    = "low"

# ── module 상수 ───────────────────────────────────────────
MODULE_SQLI = "sqli"
MODULE_XSS  = "xss"


def make_finding(
    module:     str,
    type:       str,
    category:   str,
    url:        str,
    confidence: str,
    evidence:   str,
    param:      Optional[str] = None,
    payload:    Optional[str] = None,
    status:     Optional[int] = None,
    extra:      Optional[dict] = None,
) -> dict:
    finding = {
        "module":     module,
        "type":       type,
        "category":   category,
        "url":        url,
        "param":      param,
        "payload":    payload,
        "status":     status,
        "confidence": confidence,
        "evidence":   evidence,
    }
    if extra:
        finding["extra"] = extra
    return finding


# ── 모듈별 헬퍼 ───────────────────────────────────────────

def sqli_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = LOW,
) -> dict:
    """SQLi finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_SQLI,
        type=SQLI_CONFIRMED,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


def xss_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
) -> dict:
    """XSS finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_XSS,
        type=XSS_CONFIRMED,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


# ── 저장/로드 ─────────────────────────────────────────────

def save_findings(findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """findings 리스트를 JSON 파일로 저장"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def load_findings(path: str = FINDINGS_FILE) -> list[dict]:
    """findings JSON 파일 로드. 없으면 빈 리스트 반환"""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def append_findings(new_findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """기존 findings에 새 결과를 추가하고 저장"""
    existing = load_findings(path)
    existing.extend(new_findings)
    save_findings(existing, path)


# ── 사용 예시 ─────────────────────────────────────────────
if __name__ == "__main__":
    examples = [
        sqli_finding(
            category="error_based",
            url="/bbs/search.php",
            param="stx",
            payload="a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#",
            status=200,
            evidence="xpath syntax error found in response",
        ),
        xss_finding(
            category="reflected",
            url="/bbs/search.php",
            param="stx",
            payload='" onmouseover=alert(1) x="',
            status=200,
            evidence="onmouseover=alert found unencoded in response",
        ),
    ]

    for f in examples:
        print(json.dumps(f, ensure_ascii=False, indent=2))
