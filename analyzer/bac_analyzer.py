from __future__ import annotations

import re
from collections import defaultdict
from difflib import SequenceMatcher
import requests

# 임계치
SIMILARITY_THRESHOLD = 0.8
VOTES_NEEDED         = 2

# 에러, 권한거부 패턴
_ERROR_PATTERNS = [
    re.compile(r'권한이?\s*없', re.IGNORECASE),
    re.compile(r'access\s+denied', re.IGNORECASE),
    re.compile(r'forbidden', re.IGNORECASE),
    re.compile(r'unauthorized', re.IGNORECASE),
    re.compile(r'관리자만\s*(?:접근|이용)', re.IGNORECASE),
    re.compile(r'잘못된\s*접근', re.IGNORECASE),
    re.compile(
        r'alert\s*\((?:[^)(]|\([^)]*\))*\)\s*;\s*(?:window\.close|history\.back|document\.location|location\.href|location\.replace|opener\.location)',
        re.IGNORECASE | re.DOTALL,
    ),
]

_STRIP_TAGS_RE = re.compile(r'<(script|style)[^>]*>.*?</\1>', re.DOTALL | re.IGNORECASE)
_HREF_RE       = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

_page_cache: dict[str, str] = {} # 이미 가져온 URL의 body 반환


# 로그인 url과 홈페이지 url의 html을 가져옴
def _fetch_body(url: str) -> str:
    if url in _page_cache:
        return _page_cache[url]
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, headers=_REQUEST_HEADERS)
        body = resp.text if resp.status_code == 200 else ""
    except Exception:
        body = ""
    _page_cache[url] = body
    return body



# =====
# 유사도 함수
# =====
# 앞 3천자 기준 문자열 유사도 검사
def _seq_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:3000], b[:3000]).ratio()


# script, style 태그 제거 후 남은 크기 비율 검사
def _size_sim(a: str, b: str) -> float:
    sa = len(_STRIP_TAGS_RE.sub("", a))
    sb = len(_STRIP_TAGS_RE.sub("", b))
    if not sa or not sb:
        return 0.0
    return min(sa, sb) / max(sa, sb)


# href 링크 집합의 유사도
def _href_sim(a: str, b: str) -> float:
    ha = set(_HREF_RE.findall(a))
    hb = set(_HREF_RE.findall(b))
    union = ha | hb
    if not union:
        return 0.0
    return len(ha & hb) / len(union)


# 위에 정의된 유사도 함수중 2개 이상이 임계값 이상일 경우 취약판정
def is_similar(a: str, b: str, threshold: float = SIMILARITY_THRESHOLD) -> bool:
    votes = [
        _seq_sim(a, b)  >= threshold,
        _size_sim(a, b) >= threshold,
        _href_sim(a, b) >= threshold,
    ]
    return sum(votes) >= VOTES_NEEDED


# =====
# 차단 판정
# =====

def _is_error_body(body: str) -> bool:
    return any(p.search(body) for p in _ERROR_PATTERNS)


# 테스트 응답이 차단된 응답인지 판정
def _is_blocked(data: dict, login_url: str, home_url: str) -> bool:
    if data["status"] != 200: # 반환 status가 200이 아닐경우
        return True
    body = data["body"]       # 권한 없음류 응답일 경우
    if _is_error_body(body):
        return True           
    if login_url:             # 로그인 url 페이지와 body가 유사한지
        login_body = _fetch_body(login_url)
        if login_body and is_similar(body, login_body):
            return True
    if home_url:              # 홈페이지 url 페이지와 body가 유사한지
        home_body = _fetch_body(home_url)
        if home_body and is_similar(body, home_body):
            return True
    return False


# =====
# 응답 추출
# =====

def _extract(r: dict) -> dict:
    body = r.get("response_body") or ""
    return {
        "status": r.get("status") or 0,
        "body":   body,
        "size":   r.get("length") or len(body),
    }


def _get_role(r: dict) -> str:
    meta = r.get("meta") or {}
    role = meta.get("role")
    if role:
        return role.lower()
    return (r.get("request_info") or {}).get("role", "unknown").lower()


def _get_scenario(r: dict) -> str:
    return ((r.get("meta") or {}).get("scenario") or "").lower()


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


# BAC 분석
def detect_bac_group(results: list[dict], login_url: str = "", home_url: str = "") -> list[dict]:
    bac_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("bac" in _vuln_type(r) or "bac_vertical" in _vuln_type(r))
    ]
    if not bac_results:
        return []

    groups: dict[str, list[dict]] = defaultdict(list)
    for r in bac_results:
        key = r.get("point") or (r.get("meta") or {}).get("scenario_id") or r.get("url")
        groups[key].append(r)

    detected: list[dict] = []

    for _point, group in groups.items(): # 결과 리스트값만 받아옴
        by_role: dict[str, dict] = {}
        for r in group:
            by_role[_get_role(r)] = r

        scenario = _get_scenario(group[0])
        url      = group[0].get("url") or ""

        # member에 대해서 guest 수직권한상승 확인
        if scenario == "member_only_guest_access":
            expected_r = by_role.get("member1")  # member 응답
            attacker_r = by_role.get("guest")    # guest 응답

            if not expected_r or not attacker_r: # 없을경우 스킵.
                continue

            attacker_data = _extract(attacker_r)
            if _is_blocked(attacker_data, login_url, home_url):
                continue

            expected_data = _extract(expected_r)
            if _is_blocked(expected_data, login_url, home_url): # 기준 응답 자체가 차단됨
                continue
            if is_similar(attacker_data["body"], expected_data["body"]):
                detected.append({
                    "result":   attacker_r,
                    "evidence": (
                        f"BAC member_only: 'guest'가 member 전용 URL '{url}'에 접근이 가능한 것 같습니다."
                        f"(size={attacker_data['size']})"
                    ),
                })

        # admin에 대해서 member, guest 수직권한상승 확인
        else:
            expected_r = by_role.get("admin")
            if not expected_r:
                continue

            expected_data = _extract(expected_r)
            if _is_blocked(expected_data, login_url, home_url): # 기준 응답 자체가 차단됨
                continue

            for role_name in ("member1", "guest"):
                attacker_r = by_role.get(role_name)
                if not attacker_r:
                    continue

                attacker_data = _extract(attacker_r)
                if _is_blocked(attacker_data, login_url, home_url):
                    continue

                if is_similar(attacker_data["body"], expected_data["body"]):
                    detected.append({
                        "result":   attacker_r,
                        "evidence": (
                            f"BAC admin only: '{role_name}'이 admin url에 접근이 가능한 것 같습니다."
                            f"(size={attacker_data['size']} vs admin={expected_data['size']}, url='{url}')"
                        ),
                    })

    return detected