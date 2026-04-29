from __future__ import annotations

import json
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
        }
    )
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def execute(
    tasks: list[dict],
    timeout: int = 10,
    delay: float = 0.0,
    output_file: str | None = None,
) -> list[dict]:
    """fuzz task -> HTTP send -> results."""

    session = _make_session()
    results: list[dict] = []

    for t in tasks:
        if delay:
            time.sleep(delay)

        point = t.get("point")
        payload = t.get("payload")
        inject_mode = t.get("inject_mode", "replace")
        inject_location = t.get("inject_location", "query")
        inject_param = t.get("inject_param")

        base: dict[str, Any] = {
            "id": t.get("id"),
            "point": point,
            "payload": payload,
            "inject_mode": inject_mode,
            "inject_location": inject_location,
            "inject_param": inject_param,
            "error": None,
        }

        url = t.get("url")
        method = str(t.get("method", "GET")).upper()

        if not url or payload is None or not inject_param:
            results.append({**base, "error": "invalid_task"})
            continue

        base_params = dict(t.get("base_params") or {})
        base_headers = dict(t.get("base_headers") or {})
        base_cookies = dict(t.get("base_cookies") or {})
        base_value = str(t.get("base_value") or "")

        if inject_mode == "append":
            injected = f"{base_value}{payload}"
        else:
            injected = str(payload)

        params = None
        data = None
        headers = dict(base_headers)
        cookies = dict(base_cookies)

        loc = str(inject_location).lower()
        if loc == "header":
            headers[str(inject_param)] = injected
            if method == "POST":
                data = dict(base_params)
            else:
                params = dict(base_params)
        elif loc == "cookie":
            cookies[str(inject_param)] = injected
            if method == "POST":
                data = dict(base_params)
            else:
                params = dict(base_params)
        elif loc == "body":
            data = dict(base_params)
            data[str(inject_param)] = injected
        else:  # query (default)
            params = dict(base_params)
            params[str(inject_param)] = injected

        started = time.perf_counter()
        try:
            if method == "POST":
                resp = session.post(
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=True,
                )
            else:
                resp = session.get(
                    url,
                    params=params,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=True,
                )

            elapsed = time.perf_counter() - started
            body_text = None
            try:
                body_text = resp.text
            except Exception:
                body_text = None

            results.append(
                {
                    **base,
                    "url": url,
                    "method": method,
                    "status": resp.status_code,
                    "length": len(resp.content) if resp.content is not None else None,
                    "elapsed": round(elapsed, 3),
                    "response_body": body_text[:5000] if body_text else None,
                }
            )
        except requests.Timeout:
            elapsed = time.perf_counter() - started
            results.append(
                {
                    **base,
                    "url": url,
                    "method": method,
                    "status": None,
                    "length": None,
                    "elapsed": round(elapsed, 3),
                    "error": "timeout",
                }
            )
        except Exception as e:
            elapsed = time.perf_counter() - started
            results.append(
                {
                    **base,
                    "url": url,
                    "method": method,
                    "status": None,
                    "length": None,
                    "elapsed": round(elapsed, 3),
                    "error": f"exception:{type(e).__name__}",
                }
            )

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    return results

