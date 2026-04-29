from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _guess_location(method: str) -> str:
    # targets.json이 제공하는 범위 내에서는 method 기반이 가장 안전함
    return "body" if method.upper() == "POST" else "query"


def build_tasks(points_meta: Any, payloads: Any, targets: Any | None = None) -> list[dict]:
    """points+payloads(+targets) -> fuzz task list."""

    if not points_meta or not payloads:
        return []

    # targets: base_params 기본값 채우기용 (없어도 동작)
    target_index: dict[tuple[str, str], dict] = {}
    if isinstance(targets, list):
        for t in targets:
            if not isinstance(t, dict):
                continue
            action = t.get("action")
            method = (t.get("method") or "").upper()
            if action and method:
                target_index[(method, _base_url(str(action)))] = t

    out: list[dict] = []
    tid = 0

    if not isinstance(points_meta, list):
        return []

    for p in points_meta:
        if not isinstance(p, dict):
            continue

        name = p.get("name")
        url = p.get("url")
        method = (p.get("method") or "GET").upper()
        param = p.get("param")
        if not (name and url and param):
            continue

        point_payloads = payloads.get(name) if isinstance(payloads, dict) else None
        if not isinstance(point_payloads, dict):
            continue

        inject_location = _guess_location(method)

        # 기본 파라미터(기본값) 구성: targets.json 기반으로 같은 endpoint를 찾아 채움
        base_params: dict[str, Any] = {}
        t = target_index.get((method, _base_url(str(url))))
        if isinstance(t, dict):
            for pr in t.get("params", []) or []:
                if not isinstance(pr, dict):
                    continue
                n = pr.get("name")
                if not n or n == param:
                    continue
                base_params[str(n)] = pr.get("default_value", "")

        for vtype, records in point_payloads.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                payload = rec.get("payload")
                if not payload:
                    continue

                meta = {"vuln_type": vtype, "type": rec.get("type"), "family": rec.get("family")}

                for mode in ("replace", "append"):
                    out.append(
                        {
                            "id": f"t{tid:06d}_{mode[0]}",
                            "point": name,
                            "url": url,
                            "method": method,
                            "inject_location": inject_location,
                            "inject_param": param,
                            "inject_mode": mode,
                            "base_params": base_params,
                            "payload": payload,
                            "meta": meta,
                        }
                    )
                    tid += 1

    return out

