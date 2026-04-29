"""
Payload Filter - LLM 생성 페이로드 품질 검증 및 필터링

역할: LLM이 생성한 페이로드가 실제로 쓸만한지 판단
     (D의 validator는 취약 여부 판단, 이 모듈은 페이로드 자체 품질 판단)

Pipeline:
    LLM 생성 → payload_parser.py → payload_filter.py → payloads.json → scanner
"""

import re
from typing import List, Dict

# ── 허용된 취약점 타입 ─────────────────────────────────────────────
ALLOWED_TYPES = {
    "SQLI_STRING",
    "SQLI_FIELD",
    "SQLI_ORDERBY",
    "SQLI_LOGIN",
    "ERROR_BASED",
    "BOOLEAN",
    "TIME_BASED",
    "TAUTOLOGY",
    "CONDITIONAL",
    "UNION",
    "REFLECTED_XSS",
    "STORED_XSS",
    "BAC",
    "MISCONFIG",
    "XXE",
    "CSV_INJECTION",
}

# ── LLM 설명 텍스트 패턴 (페이로드가 아닌 것들) ─────────────────────
LLM_NOISE_PATTERNS = [
    r"^(note|i cannot|here are|sure|below|example|output|payload)[\s:]",
    r"^(this|the following|as requested|generating)",
    r"^\d+\.",          # "1. 2. 3." 넘버링
    r"^[-*•]\s",        # 불릿 포인트
    r"^#",              # 마크다운 헤더
    r"^```",            # 코드블록
    r"^\s*$",           # 빈 줄
]

# ── 타입별 최소 패턴 (이게 없으면 페이로드라고 보기 어려움) ─────────────
TYPE_PATTERNS = {
    "SQLI_STRING":   [r"'", r"--", r"OR", r"AND", r"SLEEP", r"UNION", r"SELECT"],
    "SQLI_FIELD":    [r"SLEEP", r"EXTRACT", r"UPDATE", r"IF\(", r"CASE"],
    "SQLI_ORDERBY":  [r"SLEEP", r"EXTRACT", r"UPDATE", r"CASE", r"IF\("],
    "SQLI_LOGIN":    [r"'", r"--", r"OR", r"AND"],
    "ERROR_BASED":   [r"EXTRACTVALUE|UPDATEXML|FLOOR|RAND|NAME_CONST"],
    "BOOLEAN":       [r"ASCII|LENGTH|SUBSTR|CASE|EXISTS"],
    "TIME_BASED":    [r"SLEEP|BENCHMARK"],
    "TAUTOLOGY":     [r"OR|AND", r"1=1|'1'='1"],
    "CONDITIONAL":   [r"IF\(|CASE"],
    "UNION":         [r"UNION\s+SELECT"],
    "REFLECTED_XSS": [r"<|>|on\w+=|javascript:|alert|eval"],
    "STORED_XSS":    [r"<|>|on\w+=|javascript:|alert|eval|fetch"],
    "BAC":           [r"/|=|\?"],
    "MISCONFIG":     [r"/|\.env|\.git|php|backup"],
    "XXE":           [r"<!|ENTITY|xml|SYSTEM"],
    "CSV_INJECTION": [r"^[=+\-@]"],
}

MIN_LENGTH = 3
MAX_LENGTH = 2000


def _is_noise(payload: str) -> bool:
    """LLM이 섞어넣은 설명 텍스트인지 확인"""
    for pattern in LLM_NOISE_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False


def _has_valid_pattern(record: Dict[str, str]) -> bool:
    """타입에 맞는 최소 패턴이 페이로드에 존재하는지 확인"""
    vuln_type = record["type"].upper()
    payload   = record["payload"]

    patterns = TYPE_PATTERNS.get(vuln_type)
    if not patterns:
        return True  # 패턴 정의 없으면 통과

    return any(re.search(p, payload, re.IGNORECASE) for p in patterns)


def _is_valid_type(record: Dict[str, str]) -> bool:
    """허용된 TYPE인지 확인"""
    return record.get("type", "").upper() in ALLOWED_TYPES


def filter_payloads(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    LLM 생성 페이로드 리스트를 필터링.

    검사 항목:
      1. type 필드가 허용된 타입인지
      2. payload 길이가 최소/최대 범위 안인지
      3. LLM 설명 텍스트가 섞인 노이즈인지
      4. 타입에 맞는 최소 패턴이 있는지
    """
    results = []
    rejected = []

    for r in records:
        payload = r.get("payload", "").strip()
        reason  = None

        if not _is_valid_type(r):
            reason = f"invalid_type: {r.get('type')}"
        elif len(payload) < MIN_LENGTH:
            reason = "too_short"
        elif len(payload) > MAX_LENGTH:
            reason = "too_long"
        elif _is_noise(payload):
            reason = "llm_noise"
        elif not _has_valid_pattern(r):
            reason = f"no_pattern_match: {r.get('type')}"

        if reason:
            rejected.append({**r, "_rejected_reason": reason})
        else:
            results.append(r)

    return results, rejected


def deduplicate(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """payload 값 기준 중복 제거 (대소문자 무시)"""
    seen = set()
    result = []
    for r in records:
        key = r["payload"].lower()
        if key not in seen:
            seen.add(key)
            result.append(r)
    return result


def clean(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """filter + deduplicate 한 번에"""
    filtered, _ = filter_payloads(records)
    return deduplicate(filtered)


def report(original: List, filtered: List, rejected: List):
    """필터링 결과 요약 출력"""
    print(f"\n{'='*50}")
    print(f"  Payload Filter 결과")
    print(f"{'='*50}")
    print(f"  입력    : {len(original)}개")
    print(f"  통과    : {len(filtered)}개")
    print(f"  제거    : {len(rejected)}개")

    if rejected:
        print(f"\n  [제거된 페이로드]")
        for r in rejected:
            print(f"    [{r.get('type'):20s}] {r.get('_rejected_reason')} | {r.get('payload', '')[:50]}")
    print()


# ── 직접 실행 시 테스트 ──────────────────────────────────────────────
if __name__ == "__main__":
    from payload_parser import parse

    mock_llm_output = """
SQLI_STRING | auth_bypass | admin'-- -
SQLI_STRING | tautology | ' OR '1'='1'-- -
REFLECTED_XSS | value_breakout | "><img src=x onerror=alert(1)>
REFLECTED_XSS | backtick | "><img src=x onerror=alert`1`>
INVALID_TYPE | garbage | something
SQLI_STRING | too_short | '
STORED_XSS | img | Note: here are the payloads
TIME_BASED | sleep | ' AND SLEEP(5)-- -
ERROR_BASED | extractvalue | ' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -
SQLI_STRING | duplicate | admin'-- -
"""

    records = parse(mock_llm_output)
    filtered, rejected = filter_payloads(records)
    final = deduplicate(filtered)
    report(records, final, rejected)

    print("최종 페이로드:")
    for r in final:
        print(f"  [{r['type']:20s}] {r['payload']}")
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
