from __future__ import annotations

import re
from urllib.parse import urlparse
from baseline.xss import get_by_context as xss_get_by_context
from baseline.sqli import get_by_sql_context

_DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(drop|delete|update|insert|alter|truncate|create|replace|rename|grant|revoke)\b",
    re.IGNORECASE,
)
_SLEEP_RE = re.compile(
    r"sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay",
    re.IGNORECASE,
)

SKIP_OPERATORS   = {"and", "or", "move"}
SKIP_FIELD_TYPES = {"checkbox", "radio"}

_XSS_REFLECTED_CONTEXTS = ("body", "attr_value", "script", "attr_href", "html_comment")

# sqli vtype -> sql context name
_SQLI_CTX_MAP = {
    "sqli_string":  "string_sq",
    "sqli_numeric": "integer",
    "sqli_field":   "field_selector",
    "sqli_orderby": "orderby",
    "sqli_login":   "auth",
}


def _is_destructive_payload(payload: str) -> bool:
    return bool(_DESTRUCTIVE_SQL_RE.search(payload or ""))


def _is_time_based_payload(payload: str) -> bool:
    """time-based payload 여부 확인."""
    return bool(_SLEEP_RE.search(payload or ""))


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _guess_location(method: str, enctype: str = "") -> str:
    """
    주입 위치 결정.
    - GET -> query
    - POST + application/json -> json
    - POST 기타 -> body (form)
    """
    if method.upper() != "POST":
        return "query"
    if "json" in (enctype or "").lower():
        return "json"
    return "body"


def _should_skip(_name: str, value: str, field_type: str) -> bool:
    if field_type in SKIP_FIELD_TYPES:
        return True
    v = str(value).strip()
    if len(v) == 1 and not _is_numeric_value(v):
        return True
    if v.lower() in SKIP_OPERATORS:
        return True
    return False


def _is_numeric_value(value: str) -> bool:
    return bool(re.match(r"^\d+$", str(value).strip()))


def _render_payload(payload: str, base_value: str) -> str:
    if not payload or "{base}" not in payload:
        return payload
    return payload.replace("{base}", str(base_value))


def _infer_types(
    field_type: str,
    action_url: str,
    param_name: str,
    default_value: str = "",
) -> list[str]:
    if "login_check" in action_url:
        if param_name in ("mb_id", "mb_password"):
            return ["sqli_login"]
    if field_type == "password":
        return ["sqli_login"]
    if field_type == "number":
        return ["sqli_numeric"]
    if field_type == "textarea":
        return ["xss_content"]
    if field_type == "select":
        return ["sqli_field"]

    is_numeric = _is_numeric_value(default_value)

    if field_type in ("text", "input", "email", "search"):
        # numeric 값이라도 text 필드는 string 우선; numeric probe를 추가로 포함
        if is_numeric:
            return ["sqli_numeric", "xss_search"]
        return ["xss_search"]

    if field_type in ("url_param", "hidden"):
        # 숫자 값이고 위치가 query → numeric + string minimal pair
        if is_numeric:
            return ["sqli_numeric", "sqli_string"]
        return ["sqli_string"]

    # fallback
    if is_numeric:
        return ["sqli_numeric", "sqli_string"]
    return ["sqli_string"]




def _get_baseline_records_by_type(vtype: str, strength: str = "INSANE") -> list[dict]:
    records: list[dict] = []
    if "xss" in vtype:
        seen_payloads: set[str] = set()
        for ctx in _XSS_REFLECTED_CONTEXTS:
            for bp in xss_get_by_context(ctx, "INSANE"):
                p = bp.get("payload")
                if p and p not in seen_payloads:
                    seen_payloads.add(p)
                    records.append({
                        "vtype":   vtype,
                        "type":    bp.get("type"),
                        "family":  "baseline_" + (bp.get("family") or ""),
                        "payload": p,
                    })
    elif "sqli" in vtype:
        ctx = _SQLI_CTX_MAP.get(vtype, "string_sq")
        for bp in get_by_sql_context(ctx, strength):
            records.append({
                "vtype":   vtype,
                "type":    bp.get("type"),
                "family":  "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })
    return records


def build_tasks(
    targets: list | None = None,
    base_cookie: dict | None = None,
    progress_callback=None,
) -> list[dict]:
    if not targets:
        return []

    out:          list[dict]   = []
    tid:          int          = 0
    seen_combos:  set[tuple]   = set()
    total = len(targets) if isinstance(targets, list) else 0

    for idx, target in enumerate(targets or []):
        if not isinstance(target, dict):
            continue

        action   = target.get("action", "")
        method   = (target.get("method") or "GET").upper()
        enctype  = target.get("enctype", "")
        # REQ-COMMON-001: enctype 기반으로 주입 위치 결정 (query/body/json)
        inject_location = _guess_location(method, enctype)
        all_params = target.get("params") or []

        if progress_callback:
            progress_callback(idx + 1, total)

        for param in all_params:
            if not isinstance(param, dict):
                continue
            if not param.get("injectable"):
                continue

            name       = param.get("name", "")
            value      = str(param.get("default_value") or "")
            field_type = param.get("field_type", "")

            if not name:
                continue
            if _should_skip(name, value, field_type):
                continue

            combo = (method, _base_url(action), name)
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            vuln_types = _infer_types(field_type, action, name, value)
            if not vuln_types:
                continue

            # numeric 파라미터에서 sqli_string은 secondary(최소 boolean pair만) 생성
            _numeric_param = _is_numeric_value(value)

            # 다른 파라미터들의 원본 값 (REQ-COMMON-004/005: 한 번에 하나만 변조)
            base_params = {
                p["name"]: str(p.get("default_value") or "")
                for p in all_params
                if isinstance(p, dict) and p.get("name") and p["name"] != name
            }

            used_payloads: set[str] = set()
            point_label = f"{_base_url(action).split('/')[-1]}_{name}"

            def _emit(
                payload: str,
                vtype:   str,
                rec_type,
                family,
                _label=point_label,
                _repeat: int = 1,
            ) -> None:
                nonlocal tid
                payload = _render_payload(payload, value)
                if not payload or payload in used_payloads:
                    return
                if _is_destructive_payload(payload):
                    print(f"[PROBE] skipped destructive payload: point={_label}")
                    return
                used_payloads.add(payload)

                task = {
                    "id":              f"t{tid:06d}_r",
                    "point":           _label,
                    "url":             action,
                    "method":          method,
                    "inject_location": inject_location,
                    "inject_param":    name,
                    "inject_mode":     "replace",
                    "base_params":     base_params,
                    "base_cookies":    base_cookie or {},
                    "base_value":      value,
                    "payload":         payload,
                    "enctype":         enctype,
                    "meta": {
                        "vuln_type": vtype,
                        "type":      rec_type,
                        "family":    family,
                    },
                }
                out.append(task)
                tid += 1

                # REQ-SQLI-015: time-based payload는 2회 이상 재현해야 confirmed 가능
                if _is_time_based_payload(payload) and _repeat == 1:
                    dup = dict(task)
                    dup["id"]   = f"t{tid:06d}_r"
                    dup["meta"] = {**task["meta"]}
                    dup["meta"]["repeat_index"] = 2
                    out.append(dup)
                    tid += 1

            # REQ-SQLI-014/REQ-SQLI-008: baseline task를 payload보다 먼저 생성 (baseline -> true -> false 순서)
            if vuln_types and any("sqli" in vt for vt in vuln_types):
                baseline_task = {
                    "id":              f"t{tid:06d}_b",
                    "point":           point_label,
                    "url":             action,
                    "method":          method,
                    "inject_location": inject_location,
                    "inject_param":    name,
                    "inject_mode":     "replace",
                    "base_params":     base_params,
                    "base_cookies":    base_cookie or {},
                    "base_value":      value,
                    "payload":         value,
                    "enctype":         enctype,
                    "meta": {
                        "vuln_type":   vuln_types[0],
                        "type":        "BASELINE",
                        "family":      "baseline",
                        "is_baseline": True,
                    },
                }
                out.append(baseline_task)
                tid += 1

            # payload 태스크 생성
            for vtype in vuln_types:
                # baseline 레코드: numeric param의 sqli_string은 boolean pair만(MINIMAL)
                baseline_strength = (
                    "MINIMAL" if (_numeric_param and vtype == "sqli_string") else "INSANE"
                )
                for rec in _get_baseline_records_by_type(vtype, baseline_strength):
                    _emit(rec.get("payload"), vtype, rec.get("type"), rec.get("family"))

    return out
