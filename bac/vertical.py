from __future__ import annotations

import argparse
import os
import re
import time
from typing import Callable
from urllib.parse import urlparse, parse_qs
from utilities import load_json
from crawl.auth import load_cookies
from findings import (
    bac_finding, save_findings,
    BAC_SUSPECTED_HIGH, BAC_SUSPECTED_MEDIUM,
    HIGH, MEDIUM,
)
import requests

ROLE_ORDER   = ("guest", "member1", "admin")
MEMBER_ROLES = {"member", "member1", "member2", "user"}
GUEST_ROLES  = {"guest"}

ADMIN_PATH_RE = re.compile(
    r"/(?:adm|admin|administrator|admincp|wp-admin|manager|manage|management|"
    r"backend|backoffice|console|control-panel|controlpanel|cpanel|dashboard|staff)(?:/|$)",
    re.IGNORECASE,
)

DESTRUCTIVE_PATH_RE = re.compile(
    r"(delete|del_|remove|update|insert|write_update|save|logout|upload|drop)",
    re.IGNORECASE,
)

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

_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def make_run_path_fn(run_dir: str) -> Callable[[str], str]:
    return lambda filename: os.path.join(run_dir, filename)


def _is_safe_get_candidate(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not DESTRUCTIVE_PATH_RE.search(path)


def _url_signature(url: str) -> tuple:
    parsed = urlparse(url)
    param_names = frozenset(parse_qs(parsed.query).keys())
    return (parsed.path, param_names)


def _fetch(url: str, cookies: dict, timeout: int) -> tuple[int, str]:
    try:
        resp = requests.get(
            url,
            cookies=cookies or {},
            headers=_REQUEST_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


def _is_blocked_body(body: str, status: int) -> bool:
    if status != 200:
        return True
    return any(p.search(body) for p in _ERROR_PATTERNS)


def collect_vertical_candidates(
    crawl_pages: list[dict],
    include_path_patterns: bool = True,
    limit: int | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    seen_sigs: set[tuple] = set()

    for page in crawl_pages:
        url = page.get("url") or ""
        if not url or not _is_safe_get_candidate(url):
            continue

        sig = _url_signature(url)
        if sig in seen_sigs:
            continue

        accessible_by = {str(r).lower() for r in page.get("accessible_by", [])}
        admin_only  = "admin" in accessible_by and not ((GUEST_ROLES | MEMBER_ROLES) & accessible_by)
        member_only = bool(MEMBER_ROLES & accessible_by) and not (GUEST_ROLES & accessible_by)

        if admin_only:
            source        = "accessible_by_admin_only"
            confidence    = "high"
            expected_role = "admin"
            attack_roles  = ["member1", "guest"]
            scenario      = "low_role_access_admin_url"
        elif member_only:
            source        = "accessible_by_member_only"
            confidence    = "high"
            expected_role = "member1"
            attack_roles  = ["guest"]
            scenario      = "member_only_guest_access"
        elif include_path_patterns and ADMIN_PATH_RE.search(urlparse(url).path):
            source        = "admin_path_pattern"
            confidence    = "low"
            expected_role = "admin"
            attack_roles  = ["member1", "guest"]
            scenario      = "low_role_access_admin_url"
        else:
            continue

        seen_sigs.add(sig)
        candidates.append({
            "url":                  url,
            "source":               source,
            "candidate_confidence": confidence,
            "accessible_by":        sorted(accessible_by),
            "expected_role":        expected_role,
            "attack_roles":         attack_roles,
            "scenario":             scenario,
        })

        if limit and len(candidates) >= limit:
            break

    return candidates


def run_vertical_probe(
    run_path_fn: Callable[[str], str],
    timeout: int = 10,
    delay: float = 0.0,
    include_path_patterns: bool = True,
    limit: int | None = None,
    progress_callback=None,
) -> list[dict]:
    crawl_file    = run_path_fn("crawl_result.json")
    findings_file = run_path_fn("bac_findings.json")

    crawl_pages  = load_json(crawl_file, [])
    role_cookies = load_cookies(run_path_fn)
    candidates   = collect_vertical_candidates(
        crawl_pages,
        include_path_patterns=include_path_patterns,
        limit=limit,
    )

    scenario_counts: dict[str, int] = {}
    for c in candidates:
        s = c.get("scenario", "unknown")
        scenario_counts[s] = scenario_counts.get(s, 0) + 1

    print(f"[BAC] vertical candidates={len(candidates)}")
    for s, cnt in sorted(scenario_counts.items()):
        print(f"[BAC] scenario {s}={cnt}")

    findings: list[dict] = []
    total = len(candidates)

    for idx, candidate in enumerate(candidates, start=1):
        url           = candidate["url"]
        expected_role = candidate["expected_role"]
        attack_roles  = candidate["attack_roles"]
        scenario      = candidate["scenario"]
        cand_conf     = candidate["candidate_confidence"]

        print(f"[BAC] [{idx}/{total}] {url}")
        exp_status, exp_body = _fetch(url, role_cookies.get(expected_role, {}), timeout)

        if _is_blocked_body(exp_body, exp_status):
            if delay:
                time.sleep(delay)
            if progress_callback:
                progress_callback(idx, total)
            continue

        for attack_role in attack_roles:
            atk_status, atk_body = _fetch(url, role_cookies.get(attack_role, {}), timeout)

            if _is_blocked_body(atk_body, atk_status):
                continue

            if exp_body != atk_body:
                continue

            if scenario == "member_only_guest_access":
                f_type   = BAC_SUSPECTED_MEDIUM
                f_conf   = MEDIUM
                evidence = (
                    f"BAC member_only: '{attack_role}'이 member 전용 URL '{url}'에 "
                    f"접근이 가능합니다. (body 완전 일치, size={len(atk_body)})"
                )
            else:
                f_type   = BAC_SUSPECTED_HIGH if cand_conf == "high" else BAC_SUSPECTED_MEDIUM
                f_conf   = HIGH if cand_conf == "high" else MEDIUM
                evidence = (
                    f"BAC admin_only: '{attack_role}'이 admin URL '{url}'에 "
                    f"접근이 가능합니다. (body 완전 일치, size={len(atk_body)})"
                )

            findings.append(bac_finding(
                type=f_type,
                category="admin_area" if "admin" in scenario else "member_area",
                url=url,
                status=atk_status,
                confidence=f_conf,
                evidence=evidence,
                extra={
                    "attack_role":   attack_role,
                    "expected_role": expected_role,
                    "scenario":      scenario,
                    "source":        candidate["source"],
                    "accessible_by": candidate.get("accessible_by", []),
                },
            ))

        if delay:
            time.sleep(delay)
        if progress_callback:
            progress_callback(idx, total)

    save_findings(findings, findings_file)
    print(f"[BAC] findings={len(findings)}, saved: {findings_file}")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default="results")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--include-path-patterns", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    run_vertical_probe(
        make_run_path_fn(args.run_dir),
        timeout=args.timeout,
        delay=args.delay,
        include_path_patterns=args.include_path_patterns,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
