# analyzer/xss_analyzer.py
from __future__ import annotations

import re
from typing import Optional
from .findings import HIGH, MEDIUM, LOW

# 위험 실행 마커 목록 (컨텍스트별)
XSS_MARKERS = (
    # Event handler 패턴
    "onerror=alert",
    "onerror=eval",
    "onerror=prompt",
    "onerror=alert`",
    "onload=alert",
    "ontoggle=alert",
    "onmouseover=alert",
    "onmouseover=alert`",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<img src=x onerror",
    # Script 태그
    "<script>alert",
    # JavaScript 프로토콜
    "javascript:alert",
    "href=javascript:",
    "<iframe src=javascript:",
    # SVG/HTML5 벡터
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
)

# HTML 인코딩 흔적 (근처에 있으면 escape 된 것으로 간주)
_ENCODED_TOKENS = (
    "&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;", "&#x3e;", "&#62;",
    "&#39;", "&amp;", "&#x27;",
)

# 컨텍스트 감지용 패턴
_SCRIPT_OPEN_RE  = re.compile(r'<script[^>]*>', re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r'</script\s*>', re.IGNORECASE)
_ATTR_URL_RE     = re.compile(
    r'\b(?:href|src|action|formaction|data|codebase|background)\s*=\s*["\']?$',
    re.IGNORECASE,
)
_HTML_ENTITY_RE  = re.compile(
    r'&(?:lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);',
    re.IGNORECASE,
)

_BLOCKED_STATUSES = frozenset({403, 406})
_MARKER_WINDOW = 200


# ─── 헬퍼 ────────────────────────────────────────────────────────

def _extract_body(test_result: dict) -> str:
    bodies = []
    if test_result.get("response_body"):
        bodies.append(test_result.get("response_body") or "")
    if test_result.get("verify_body"):
        bodies.append(test_result.get("verify_body") or "")
    if "response" in test_result and isinstance(test_result["response"], dict):
        bodies.append(test_result["response"].get("body") or "")
    return "\n".join(bodies)


def _find_payload_in_body(payload: str, body_raw: str) -> int:
    """payload의 시작 위치를 반환. 없으면 -1."""
    if not payload or not body_raw:
        return -1
    return body_raw.lower().find(payload.lower())


def _is_encoded(body: str, idx: int, marker_len: int, window: int = 20) -> bool:
    """REQ-XSS-005/006: 마커 주변에 HTML 인코딩 흔적이 있으면 escape 된 것으로 판단."""
    start = max(0, idx - window)
    end   = idx + marker_len + window
    surrounding = body[start:end]
    return any(tok in surrounding for tok in _ENCODED_TOKENS)


def _classify_reflection_context(body: str, needle: str) -> str:
    """
    응답 HTML 내에서 payload가 반사된 위치의 컨텍스트 분류.

    반환값:
        html_text       - <tag>PAYLOAD</tag> 일반 텍스트 노드
        html_attribute  - <tag attr="PAYLOAD"> 속성 값
        script_block    - <script>...PAYLOAD...</script>
        url_attribute   - <a href="PAYLOAD">, <img src="PAYLOAD"> 등
        html_comment    - <!-- PAYLOAD -->
        unknown         - 판단 불가
    """
    if not needle or not body:
        return "unknown"

    idx = body.find(needle)
    if idx == -1:
        idx = body.lower().find(needle.lower())
    if idx == -1:
        return "unknown"

    prefix = body[:idx]

    # 1. HTML 주석 내부?
    last_comment_open  = prefix.rfind("<!--")
    last_comment_close = prefix.rfind("-->")
    if last_comment_open > last_comment_close:
        return "html_comment"

    # 2. <script> 블록 내부?
    script_opens  = [m.end() for m in _SCRIPT_OPEN_RE.finditer(prefix)]
    script_closes = [m.start() for m in _SCRIPT_CLOSE_RE.finditer(prefix)]
    if script_opens:
        last_open  = script_opens[-1]
        last_close = script_closes[-1] if script_closes else -1
        if last_open > last_close:
            return "script_block"

    # 3. HTML 태그 속성 내부?
    last_lt = prefix.rfind("<")
    last_gt = prefix.rfind(">")
    if last_lt > last_gt:
        attr_context = prefix[last_lt:]
        if _ATTR_URL_RE.search(attr_context):
            return "url_attribute"
        return "html_attribute"

    return "html_text"


def _is_payload_html_escaped(payload: str, body: str) -> bool:
    """
    payload 핵심 문자('<', '>', '"')가 HTML 엔티티로 변환되어 반사됐는지 확인
    """
    if not payload or not body:
        return False
    # payload에 angle bracket 또는 quote가 없으면 escaping 여부 판단 불필요
    has_angle = "<" in payload or ">" in payload
    has_quote = '"' in payload or "'" in payload
    if not has_angle and not has_quote:
        return False
    # body에서 payload 위치 찾기
    idx = body.lower().find(payload.lower()[:15])
    if idx == -1:
        return False
    window = body[max(0, idx - 5):idx + len(payload) + 30]
    return bool(_HTML_ENTITY_RE.search(window))


# ─── 마커 체크 ───────────────────────────────────────────────────

def _check_markers_near_payload(
    payload: str, body_raw: str, pay_idx: int
) -> Optional[tuple[str, str]]:
    """
    pay_idx 주변 _MARKER_WINDOW bytes 범위에서만 위험 마커를 검색한다.
    body 전체 스캔 시 페이지 자체 JS가 오탐으로 잡히던 문제를 방지한다.
    pay_idx는 호출자가 이미 계산한 값을 받아 중복 find() 호출을 없앤다.
    """
    region_start = max(0, pay_idx - _MARKER_WINDOW)
    region_end   = pay_idx + len(payload) + _MARKER_WINDOW
    region       = body_raw[region_start:region_end]
    region_lower = region.lower()

    for marker in XSS_MARKERS:
        m_idx = region_lower.find(marker)
        if m_idx == -1:
            continue
        if _is_encoded(region, m_idx, len(marker)):
            continue
        abs_start    = region_start + m_idx
        raw_fragment = body_raw[abs_start: abs_start + len(marker)]
        context      = _classify_reflection_context(body_raw, raw_fragment)
        return marker, context
    return None


# ─── 페이로드 반사 체크 ──────────────────────────────────────────

def _check_payload_reflection(
    payload: str, body_raw: str
) -> Optional[tuple[str, bool, str]]:
    """
    payload 반사 여부 확인.
    반환: (evidence, is_escaped, context) or None

    단순 반사만으로 confirmed 불가 — 호출자가 판정.
    """
    if not payload:
        return None
    pl = payload.strip()
    if len(pl) < 4:
        return None

    idx = body_raw.lower().find(pl.lower())
    if idx == -1:
        return None

    is_escaped = _is_encoded(body_raw, idx, len(pl)) or _is_payload_html_escaped(pl, body_raw)
    raw_fragment = body_raw[idx: idx + len(pl)]
    context = _classify_reflection_context(body_raw, raw_fragment)
    return "페이로드 반사됨", is_escaped, context


# ─── 메인 진입점 ─────────────────────────────────────────────────

def validate_xss(test_result: dict) -> tuple[bool, str, str]:
    """
    (found, evidence, confidence) 반환.

    반사 없으면 취약 아님
    escape 된 반사 → info/제외 (False 반환)
    위험 컨텍스트 + 미escape → medium/high
    단순 문자열 반사만으로 confirmed/high 금지
    """
    if not test_result:
        return False, "검증 불가 (입력 없음)", ""

    # 게이트 1: 차단 응답
    status = test_result.get("status")
    if status in _BLOCKED_STATUSES:
        return False, f"차단 응답 (HTTP {status}) — XSS 판정 불가", ""

    body_raw = _extract_body(test_result)
    if not body_raw:
        return False, "검증 불가 (응답 본문 없음)", ""

    payload = test_result.get("payload") or ""

    # 게이트 2: payload 반사 여부 확인 (위치도 확보해 중복 find() 방지)
    pay_idx = _find_payload_in_body(payload, body_raw)
    if not payload or pay_idx == -1:
        return False, "응답에 payload 미반사 — XSS 판정 불가", ""

    # 마커 체크 (payload 위치 주변만)
    marker_result = _check_markers_near_payload(payload, body_raw, pay_idx)
    if marker_result:
        marker, context = marker_result
        # REQ-XSS-004: 컨텍스트에 따라 신뢰도 결정
        if context in ("script_block", "url_attribute"):
            confidence = HIGH
        elif context == "html_attribute":
            confidence = MEDIUM
        else:
            confidence = MEDIUM
        return True, f"XSS 위험 마커 노출 [{context}] ('{marker[:40]}')", confidence

    # 2. 페이로드 반사 체크
    refl = _check_payload_reflection(payload, body_raw)
    if refl:
        _, is_escaped, context = refl

        # REQ-XSS-012: escape 된 반사 → 실행 불가, 취약 아님
        if is_escaped:
            return False, f"XSS payload escape됨 [{context}] — 실행 불가", ""

        # 단순 반사만으로 confirmed/high 금지
        # 위험 컨텍스트 + 미escape → medium
        if context in ("script_block", "html_attribute", "url_attribute"):
            return (
                True,
                f"XSS payload 반사 (미escape, 위험 컨텍스트: {context}) — 수동 확인 필요",
                MEDIUM,
            )

        # html_text/unknown: 단순 반사 → confirmed 불가
        return False, f"XSS payload 반사 (비위험 컨텍스트: {context}) — 단순 반사, confirmed 불가", ""

    # 반사 없음
    return False, "안전함 (XSS 시그니처 미검출 / 인코딩됨)", ""
