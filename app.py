import importlib
import time
import json
import os
import io
import queue
import secrets
import subprocess
import sys
import shutil
import threading
from datetime import datetime
import report as report_gen


from utilities import load_json, normalize_base_url, save_json
from dotenv import load_dotenv
from flask import Flask, Response, redirect, render_template, request, send_file, jsonify
from tasks import (
    _task_crawl as _crawl_impl,
    _task_probe as _probe_impl,
    _task_execute as _execute_impl,
    _task_validate as _validate_impl,
    _task_misconfig as _misconfig_impl,
    _task_bac_stream as _bac_impl,
    _task_main_stream as _all_impl,
    TASK_LABELS as _TASK_LABELS,
)

_DEPS = {
    "flask": "flask",
    "python-dotenv": "dotenv",
    "requests": "requests",
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
}

for _pkg, _mod in _DEPS.items():
    try:
        importlib.import_module(_mod)
    except ImportError:
        print(f"[INSTALL] {_pkg} installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "-q"])
del _pkg, _mod

load_dotenv()


TARGETS_CONFIG_FILE = "targets_config.json"
ACTIVE_TARGET_FILE  = "active_target.json"
RUNS_DIR = "runs"

def _load_targets() -> list[dict]:
    if os.path.exists(TARGETS_CONFIG_FILE):
        targets = load_json(TARGETS_CONFIG_FILE, None)
        if targets is not None:
            return targets
    return [
        {
            "key": "primary",
            "name": "기본 타깃",
            "url": os.getenv("TARGET_URL", "http://localhost"),
            "cms": "custom",
            "login_url": os.getenv("LOGIN_URL", ""),
            "login_id": os.getenv("LOGIN_ID_1", ""),
            "login_password": os.getenv("LOGIN_PASSWORD_1", ""),
            "login_id_2": os.getenv("LOGIN_ID_2", ""),
            "login_password_2": os.getenv("LOGIN_PASSWORD_2", ""),
            "admin_id": os.getenv("ADMIN_ID", ""),
            "admin_password": os.getenv("ADMIN_PASSWORD", ""),
            "login_fail_indicator": os.getenv("LOGIN_FAIL_INDICATOR", ""),
        }
    ]


def _save_targets(targets: list[dict]) -> None:
    save_json(TARGETS_CONFIG_FILE, targets)


def _load_active_target_key(targets: list[dict]) -> str:
    if os.path.exists(ACTIVE_TARGET_FILE):
        data = load_json(ACTIVE_TARGET_FILE, {})
        key = data.get("key", "")
        if any(t["key"] == key for t in targets):
            return key
    return targets[0]["key"] if targets else ""


def _save_active_target_key(key: str) -> None:
    save_json(ACTIVE_TARGET_FILE, {"key": key})


def _apply_active_target_env(target: dict) -> None:
    mapping = {
        "TARGET_URL": target.get("url", ""),
        "LOGIN_URL": target.get("login_url", ""),
        "LOGIN_ID_1": target.get("login_id", ""),
        "LOGIN_PASSWORD_1": target.get("login_password", ""),
        "LOGIN_ID_2": target.get("login_id_2", ""),
        "LOGIN_PASSWORD_2": target.get("login_password_2", ""),
        "ADMIN_ID": target.get("admin_id", ""),
        "ADMIN_PASSWORD": target.get("admin_password", ""),
        "LOGIN_FAIL_INDICATOR": target.get("login_fail_indicator", ""),
    }
    for k, v in mapping.items():
        os.environ[k] = v
    try:
        import crawl.auth as _auth
        _auth.LOGIN_URL = mapping["LOGIN_URL"]
        _auth.LOGIN_ID_1 = mapping["LOGIN_ID_1"]
        _auth.LOGIN_PASSWORD_1 = mapping["LOGIN_PASSWORD_1"]
        _auth.LOGIN_ID_2 = mapping["LOGIN_ID_2"]
        _auth.LOGIN_PASSWORD_2 = mapping["LOGIN_PASSWORD_2"]
        _auth.ADMIN_ID = mapping["ADMIN_ID"]
        _auth.ADMIN_PASSWORD = mapping["ADMIN_PASSWORD"]
        _auth.LOGIN_FAIL_INDICATOR = mapping["LOGIN_FAIL_INDICATOR"]
    except ImportError:
        pass


_TARGETS: list[dict] = _load_targets()
_active_target_key: str = _load_active_target_key(_TARGETS)
_active_target = next((t for t in _TARGETS if t["key"] == _active_target_key), _TARGETS[0] if _TARGETS else None)
if _active_target:
    _apply_active_target_env(_active_target)
_current_run_id: str | None = None

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.jinja_env.auto_reload = True
_task_lock    = threading.Lock()
_thread_local = threading.local()
_running_task: str | None = None

# ── 브로드캐스트 로그 버퍼 ──────────────────────────────────────
_log_lock        = threading.Lock()
_log_buffer:     list[str] = []       # 최근 500줄 보관
_log_subscribers: list[queue.Queue] = []
_LOG_BUF_MAX = 500

# ── 로그 파일 / 파이프라인 타이밍 ────────────────────────────────
_log_file_handle = None
_step_timing: dict[str, float] = {}   # {"crawl": 12.3, ...}


def _open_log_file(run_dir: str) -> None:
    global _log_file_handle
    _close_log_file()
    try:
        _log_file_handle = open(os.path.join(run_dir, "scan.log"), "w", encoding="utf-8")
    except Exception:
        pass


def _close_log_file() -> None:
    global _log_file_handle
    if _log_file_handle:
        try:
            _log_file_handle.close()
        except Exception:
            pass
        _log_file_handle = None


def _save_timing(run_dir: str) -> None:
    try:
        import json as _json
        with open(os.path.join(run_dir, "timing.json"), "w", encoding="utf-8") as f:
            _json.dump(_step_timing, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _broadcast(msg: str) -> None:
    global _step_timing
    with _log_lock:
        _log_buffer.append(msg)
        if len(_log_buffer) > _LOG_BUF_MAX:
            _log_buffer.pop(0)

        # 로그 파일 저장 (__PROGRESS__ 제외, 나머지 전부 기록)
        if _log_file_handle and not msg.startswith("__PROGRESS__"):
            try:
                from datetime import datetime as _dt
                _log_file_handle.write(f"[{_dt.now().strftime('%H:%M:%S')}] {msg}\n")
                _log_file_handle.flush()
            except Exception:
                pass

        # 파이프라인 타이밍 파싱: __TIMING__step_name:seconds
        if msg.startswith("__TIMING__"):
            try:
                payload = msg[len("__TIMING__"):]
                step, secs = payload.split(":", 1)
                _step_timing[step.strip()] = float(secs.strip())
                if _current_run_id:
                    _save_timing(os.path.join(RUNS_DIR, _current_run_id))
            except Exception:
                pass

        for sub in _log_subscribers:
            try:
                sub.put_nowait(msg)
            except queue.Full:
                pass

def _subscribe() -> queue.Queue:
    """새 SSE 클라이언트 등록 + 버퍼 기존 로그 전달."""
    q: queue.Queue = queue.Queue(maxsize=2000)
    with _log_lock:
        for msg in _log_buffer:
            try:
                q.put_nowait(msg)
            except queue.Full:
                break
        _log_subscribers.append(q)
    return q

def _unsubscribe(q: queue.Queue) -> None:
    with _log_lock:
        if q in _log_subscribers:
            _log_subscribers.remove(q)




def _run_task_name(run_type: str) -> str:
    return "all" if run_type == "main" else run_type


def _make_run_id(run_type: str) -> str:
    task_name = _run_task_name(run_type)
    date_part = datetime.now().strftime("%Y%m%d")
    random_part = secrets.token_hex(3)
    return f"run-{task_name}-{date_part}-{random_part}"


def _is_run_id(name: str) -> bool:
    return name.startswith("run_") or name.startswith("run-")


def _run_created_label(run_id: str) -> str:
    try:
        return datetime.strptime(run_id, "run_%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    parts = run_id.split("-")
    if len(parts) >= 4 and parts[0] == "run":
        try:
            return datetime.strptime(parts[2], "%Y%m%d").strftime("%Y-%m-%d")
        except Exception:
            pass
    return run_id


def _run_dir(run_id: str) -> str:
    return os.path.join(RUNS_DIR, run_id)


def _infer_run_type(run_id: str) -> str:
    run_dir = _run_dir(run_id)
    meta = load_json(os.path.join(run_dir, "run_meta.json"), {})
    run_type = meta.get("run_type")
    if run_type in {"main", "bac"}:
        return run_type

    try:
        files = set(os.listdir(run_dir))
    except Exception:
        return "main"
    if "bac_vertical_results.json" in files or "bac_findings.json" in files or "bac_vertical_tasks.json" in files:
        return "bac"
    return "main"


def _write_run_meta(run_id: str, run_type: str) -> None:
    meta = {
        "run_type": run_type,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "target_url": _active_url(),
    }
    save_json(os.path.join(_run_dir(run_id), "run_meta.json"), meta)


def _create_run(run_type: str) -> str:
    run_id = _make_run_id(run_type)
    os.makedirs(_run_dir(run_id), exist_ok=True)
    _write_run_meta(run_id, run_type)
    return run_id


def _list_run_ids() -> list[str]:
    if not os.path.exists(RUNS_DIR):
        return []
    return sorted(
        [
            d for d in os.listdir(RUNS_DIR)
            if os.path.isdir(os.path.join(RUNS_DIR, d)) and _is_run_id(d)
        ],
        reverse=True,
    )


def _latest_run_id(run_type: str | None = None) -> str | None:
    for run_id in _list_run_ids():
        if run_type is None or _infer_run_type(run_id) == run_type:
            return run_id
    return None


def _init_run() -> None:
    global _current_run_id
    os.makedirs(RUNS_DIR, exist_ok=True)
    existing = _list_run_ids()
    if existing:
        _current_run_id = existing[0]
    else:
        _current_run_id = _create_run("main")


def _run_path(filename: str, run_id: str | None = None) -> str:
    return os.path.join(RUNS_DIR, run_id or _current_run_id or "default", filename)



def _active_url() -> str:
    target = next((t for t in _TARGETS if t["key"] == _active_target_key), _TARGETS[0] if _TARGETS else {})
    return target.get("url", "")


def _emit_progress(pct: int) -> None:
    _broadcast(f"__PROGRESS__{max(0, min(100, int(pct)))}")


class _RoutingStream:
    def __init__(self, original):
        self._orig = original

    def write(self, text):
        if _running_task is not None:
            stripped = text.rstrip("\n")
            if stripped:
                _broadcast(stripped)
        else:
            self._orig.write(text)

    def flush(self):
        self._orig.flush()

    def __getattr__(self, name):
        return getattr(self._orig, name)


sys.stdout = _RoutingStream(sys.__stdout__)


def _task_crawl():
    _crawl_impl(_run_path, _active_url(), _emit_progress)


def _task_probe():
    _probe_impl(_run_path, _emit_progress)


def _task_execute():
    _execute_impl(_run_path, _emit_progress)


def _task_validate():
    _validate_impl(_run_path, _emit_progress)


def _task_misconfig():
    _misconfig_impl(_run_path, _active_url(), _emit_progress)


def _task_all(skip_crawl: bool = False, resume: bool = False):
    _all_impl(_run_path, _active_url(), _run_path("payloads.json"), _run_path("payloads_meta.json"), skip_crawl=skip_crawl, resume=resume, emit_progress=_emit_progress)

def _task_bac():
    _bac_impl(_run_path, _active_url(), _emit_progress)

_TASK_FUNCS = {
    "crawl":    _task_crawl,
    "probe":    _task_probe,
    "execute":  _task_execute,
    "validate": _task_validate,
    "misconfig": _task_misconfig,
    "bac":      _task_bac,
    "all":      _task_all,
}


@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl = request.args.get("skip_crawl") == "1"
    resume     = request.args.get("resume") == "1"

    # 이미 실행 중이면 태스크를 새로 시작하지 않고 기존 브로드캐스트에 구독만
    already_running = _running_task is not None

    global _current_run_id
    if not already_running:
        if task == "all" and resume:
            current_main = _current_run_id if _current_run_id and _infer_run_type(_current_run_id) == "main" else None
            resume_run = current_main or _latest_run_id("main")
            if resume_run:
                _current_run_id = resume_run
            else:
                _current_run_id = _create_run("main")
                resume = False
        elif task == "all" and skip_crawl:
            latest_main_run = _latest_run_id("main")
            if latest_main_run:
                _current_run_id = latest_main_run
            else:
                _current_run_id = _create_run("main")
                skip_crawl = False
        elif task == "all":
            _current_run_id = _create_run("main")
        elif task == "bac":
            _current_run_id = _create_run("bac")

        with _log_lock:
            _log_buffer.clear()
            _step_timing.clear()
        _open_log_file(os.path.join(RUNS_DIR, _current_run_id))

        def run_in_thread():
            global _running_task
            acquired = _task_lock.acquire(blocking=False)
            if not acquired:
                _broadcast("__SYSTEM__ [WARN] 다른 태스크가 실행 중입니다.")
                _broadcast("__DONE__")
                return
            _running_task = task
            label = _TASK_LABELS.get(task, task)
            _broadcast(f"[{label}] 시작")
            try:
                if task == "all":
                    _task_all(skip_crawl=skip_crawl, resume=resume)
                else:
                    _TASK_FUNCS[task]()
            except Exception as exc:
                _broadcast(f"[ERROR] {type(exc).__name__}: {exc}")
            finally:
                _running_task = None
                _task_lock.release()
                _broadcast(f"[{label}] 완료")
                _broadcast("__DONE__")
                _close_log_file()

        threading.Thread(target=run_in_thread, daemon=True).start()

    # 구독 시작 (실행 중이면 버퍼 로그 + 이후 로그 수신)
    sub = _subscribe()

    def generate():
        try:
            while True:
                try:
                    msg = sub.get(timeout=2)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                if msg == "__DONE__":
                    yield "data: __DONE__\n\n"
                    break
                safe = msg.replace("\n", " ")
                yield f"data: {safe}\n\n"
        finally:
            _unsubscribe(sub)

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _list_runs() -> list[dict]:
    if not os.path.exists(RUNS_DIR):
        return []
    runs = []
    for d in sorted(os.listdir(RUNS_DIR), reverse=True):
        full = os.path.join(RUNS_DIR, d)
        if not os.path.isdir(full) or not d.startswith("run_"):
            continue
        files = set(os.listdir(full))
        ts = _run_created_label(d)
        run_type = _infer_run_type(d)

        findings_cnt = 0
        for findings_file in ("findings.json", "bac_findings.json"):
            if findings_file in files:
                findings_cnt += len(load_json(os.path.join(full, findings_file), []))

        runs.append({
            "id": d,
            "ts": ts,
            "run_type": run_type,
            "is_current": d == _current_run_id,
            "has_crawl": "crawl_result.json" in files,
            "has_exec": "execution_results.json" in files or "bac_vertical_results.json" in files,
            "has_findings": "findings.json" in files or "bac_findings.json" in files,
            "findings_cnt": findings_cnt,
        })
    return runs


def _get_file_status():
    return [
        ("크롤링 결과", os.path.exists(_run_path("crawl_result.json"))),
        ("타깃 목록", os.path.exists(_run_path("targets.json"))),
        ("탐색 작업 목록", os.path.exists(_run_path("probe_tasks.json"))),
        ("실행 결과", os.path.exists(_run_path("execution_results.json"))),
        ("취약점 결과", os.path.exists(_run_path("findings.json"))),
    ]


def _get_quick_summary():
    scan_file = _run_path("scan_results.json")
    if not os.path.exists(scan_file):
        return None
    try:
        results = load_json(scan_file, [])
        total = len(results)
        vulns = sum(1 for r in results if r.get("vulnerable"))
        return {"total": total, "vulns": vulns, "rate": vulns / max(total, 1) * 100}
    except Exception:
        return None


def _get_exec_summary():
    exec_file = _run_path("execution_results.json")
    if not os.path.exists(exec_file):
        return None
    try:
        results = load_json(exec_file, [])
        total = len(results)
        ok = sum(1 for r in results if r.get("error") is None)
        timeout = sum(1 for r in results if r.get("error") == "timeout")
        return {"total": total, "ok": ok, "timeout": timeout}
    except Exception:
        return None


def _misconfig_done() -> bool:
    p = _run_path("findings.json")
    if not os.path.exists(p):
        return False
    try:
        findings = load_json(p, [])
        return any(fi.get("module") == "misconfig" for fi in findings)
    except Exception:
        return False


def _get_pipeline_steps():
    checks = [
        ("crawl",    "크롤러",         "travel_explore", os.path.exists(_run_path("crawl_result.json")) and os.path.exists(_run_path("targets.json"))),
        ("probe",    "주입 테스트 준비", "radar",          os.path.exists(_run_path("probe_tasks.json"))),
        ("execute",  "실행기",         "terminal",       os.path.exists(_run_path("execution_results.json"))),
        ("validate", "분석기",         "analytics",      os.path.exists(_run_path("findings.json"))),
    ]
    active_assigned = False
    steps = []
    for key, label, icon, complete in checks:
        state = "complete" if complete else "pending"
        if not complete and not active_assigned:
            state = "active"
            active_assigned = True
        steps.append({"key": key, "label": label, "icon": icon, "state": state})
    return steps


def _get_pipeline_progress():
    steps = _get_pipeline_steps()
    complete = sum(1 for step in steps if step["state"] == "complete")
    total = max(len(steps), 1)
    return {"complete": complete, "total": total, "percent": int(round(complete / total * 100))}


def _get_target_envs():
    result = []
    for target in _TARGETS:
        is_active = target["key"] == _active_target_key
        result.append({
            **target,
            "is_active": is_active,
            "status": "active" if is_active else "standby",
            "status_label": "스캔 대상" if is_active else "대기 중",
            "last_scanned": _current_run_id or "-" if is_active else "-",
        })
    return result


@app.route("/")
def index():
    print("index")
    return render_template(
        "index.html",
        base_url=_active_url(),
        file_status=_get_file_status(),
        pipeline_steps=_get_pipeline_steps(),
        pipeline_progress=_get_pipeline_progress(),
        summary=_get_quick_summary(),
        exec_summary=_get_exec_summary(),
        targets=_get_target_envs(),
        current_run=_current_run_id or "",
    )


@app.route("/bac")
def bac_page():
    bac_findings_file = _run_path("bac_findings.json")
    all_findings = load_json(bac_findings_file, [])
    bac_findings = [f for f in all_findings if f.get("module") != "misconfig"]
    misconfig_findings = [f for f in all_findings if f.get("module") == "misconfig"]
    return render_template(
        "bac.html",
        bac_findings=bac_findings,
        bac_cnt=len(bac_findings),
        misconfig_findings=misconfig_findings,
        misconfig_cnt=len(misconfig_findings),
        has_crawl=os.path.exists(_run_path("crawl_result.json")),
        has_bac_results=os.path.exists(_run_path("bac_vertical_results.json")),
        has_bac_findings=os.path.exists(bac_findings_file),
        has_misconfig=len(misconfig_findings) > 0,
        current_run=_current_run_id or "",
    )


@app.route("/results")
def results_page():
    return redirect("/findings")


def _group_findings_by_url(findings: list[dict]) -> list[dict]:
    from collections import defaultdict
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        url = f.get("url") or f.get("point") or "unknown"
        groups[url].append(f)

    result = []
    for url, items in groups.items():
        danger  = sum(1 for f in items if "CONFIRMED" in (f.get("type") or ""))
        warning = sum(1 for f in items if "WARNING"   in (f.get("type") or ""))
        slim_items = [
            {
                "status_label": "danger" if "CONFIRMED" in (f.get("type") or "") else "warning",
                "vuln_type":    f.get("module") or "",
                "param":        f.get("param") or "",
                "payload":      str(f.get("payload") or "")[:120],
                "status":       f.get("status"),
                "evidence":     str(f.get("evidence") or "")[:200],
            }
            for f in items
        ]
        result.append({
            "url":     url,
            "danger":  danger,
            "warning": warning,
            "error":   0,
            "safe":    0,
            "total":   len(items),
            "items":   slim_items,
        })

    return sorted(result, key=lambda x: (-x["danger"], -x["warning"], -x["total"]))


def _group_results_by_url(all_results: list[dict]) -> list[dict]:
    from collections import defaultdict
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in all_results:
        url = r.get("url") or r.get("point") or "unknown"
        groups[url].append(r)

    result = []
    for url, items in groups.items():
        danger  = sum(1 for r in items if r.get("_vulnerable"))
        warning = sum(1 for r in items if r.get("_warning") and not r.get("_vulnerable"))
        error   = sum(1 for r in items if r.get("error") and not r.get("_vulnerable") and not r.get("_warning"))
        safe    = len(items) - danger - warning - error
        slim_items = [
            {
                "status_label": "danger" if r.get("_vulnerable") else "warning" if r.get("_warning") else "error" if r.get("error") else "safe",
                "vuln_type":    r.get("_vuln_type") or "",
                "param":        r.get("inject_param") or "",
                "payload":      str(r.get("payload") or "")[:120],
                "status":       r.get("status"),
                "evidence":     str(r.get("_evidence") or "")[:200],
            }
            for r in items
        ]
        result.append({
            "url":     url,
            "danger":  danger,
            "warning": warning,
            "error":   error,
            "safe":    safe,
            "total":   len(items),
            "items":   slim_items,
        })

    return sorted(result, key=lambda x: (-x["danger"], -x["warning"], -x["total"]))


@app.route("/findings")
def findings_page():
    run_id = request.args.get("run") or _current_run_id
    findings_file = _run_path("findings.json", run_id=run_id)
    exec_file = _run_path("execution_results.json", run_id=run_id)
    bac_findings_file = _run_path("bac_findings.json", run_id=run_id)
    bac_exec_file = _run_path("bac_vertical_results.json", run_id=run_id)

    findings = []
    if os.path.exists(findings_file):
        try:
            with open(findings_file, encoding="utf-8") as f:
                findings = json.load(f)
        except Exception as exc:
            return f"결과 파일 읽기 오류: {exc}", 500

    findings.extend(load_json(bac_findings_file, []))

    xss_cnt       = sum(1 for f in findings if f.get("module") == "xss")
    sqli_cnt      = sum(1 for f in findings if f.get("module") == "sqli")
    bac_cnt       = sum(1 for f in findings if f.get("module") == "bac")
    misconfig_cnt = sum(1 for f in findings if f.get("module") == "misconfig")

    all_results = []
    safe_cnt = 0
    if os.path.exists(exec_file):
        try:
            findings_by_id = {f.get("id"): f for f in findings}
            exec_results = load_json(exec_file, [])
            for r in exec_results:
                hit = findings_by_id.get(r.get("id"))
                verdict = (hit.get("extra") or {}).get("verdict", "confirmed") if hit else None
                r["_vulnerable"] = hit is not None and verdict == "confirmed"
                r["_warning"]    = hit is not None and verdict in ("suspected", "candidate")
                r["_evidence"] = hit.get("evidence", "") if hit else ""
                r["_vuln_type"] = hit.get("type") or hit.get("module", "") if hit else (r.get("meta") or {}).get("vuln_type", "")
                r["_extra"] = hit.get("extra") or {} if hit else {}
            all_results = exec_results
        except Exception:
            pass

    if os.path.exists(bac_exec_file):
        try:
            findings_by_id = {f.get("id"): f for f in findings}
            bac_exec_results = load_json(bac_exec_file, [])
            for r in bac_exec_results:
                hit = findings_by_id.get(r.get("id"))
                meta = r.get("meta") or {}
                r["_vulnerable"] = hit is not None
                r["_evidence"] = hit.get("evidence", "") if hit else ""
                r["_vuln_type"] = hit.get("module", "") if hit else meta.get("vuln_type", "bac")
                r["_role"] = meta.get("role", "")
            all_results.extend(bac_exec_results)
        except Exception:
            pass

    for mf in findings:
        if mf.get("module") != "misconfig":
            continue
        is_confirmed = mf.get("type") == "MISCONFIG_CONFIRMED"
        all_results.append({
            "_vulnerable":  is_confirmed,
            "_warning":     not is_confirmed,
            "_evidence":    mf.get("evidence", ""),
            "_vuln_type":   mf.get("type", "misconfig"),
            "_extra":       mf.get("extra") or {},
            "url":          mf.get("url", ""),
            "method":       "GET",
            "inject_param": None,
            "payload":      "",
            "status":       mf.get("status"),
            "error":        None,
        })

    safe_cnt = sum(1 for r in all_results if not r.get("_vulnerable") and not r.get("_warning") and not r.get("error"))

    url_groups = _group_results_by_url(all_results)

    return render_template(
        "findings.html",
        findings=findings,
        xss_cnt=xss_cnt,
        sqli_cnt=sqli_cnt,
        bac_cnt=bac_cnt,
        misconfig_cnt=misconfig_cnt,
        safe_cnt=safe_cnt,
        all_results=all_results,
        url_groups=url_groups,
        run_id=run_id,
        current_run=_current_run_id,
    )


@app.route("/exec_results")
def exec_results_page():
    run_id = request.args.get("run") or _current_run_id
    exec_file = _run_path("execution_results.json", run_id=run_id)
    if not os.path.exists(exec_file):
        return render_template("exec_results.html", results=None, total=0, ok=0, timeout=0, err=0, run_id=run_id, current_run=_current_run_id)
    try:
        with open(exec_file, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500
    total = len(results)
    ok = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    return render_template("exec_results.html", results=results, total=total, ok=ok, timeout=timeout, err=err, run_id=run_id, current_run=_current_run_id)


@app.route("/targets")
def targets_page():
    saved = request.args.get("saved") == "1"
    open_key = request.args.get("open", "")
    return render_template("targets.html", targets=_get_target_envs(), saved=saved, open_key=open_key)


@app.route("/targets/set", methods=["POST"])
def set_target():
    global _active_target_key
    key = request.form.get("key")
    target = next((t for t in _TARGETS if t["key"] == key), None)
    if target:
        _active_target_key = key
        _apply_active_target_env(target)
        _save_active_target_key(key)
    return redirect("/targets")


@app.route("/targets/add", methods=["POST"])
def add_target():
    name = request.form.get("name", "").strip()
    url = normalize_base_url(request.form.get("url", ""))
    if not name or not url:
        return redirect("/targets")
    key = f"target_{int(time.time())}"
    _TARGETS.append({
        "key": key,
        "name": name,
        "url": url,
        "cms": "custom",
        "login_url": "",
        "login_id": "",
        "login_password": "",
        "login_id_2": "",
        "login_password_2": "",
        "admin_id": "",
        "admin_password": "",
        "login_fail_indicator": "",
    })
    _save_targets(_TARGETS)
    return redirect("/targets")


@app.route("/targets/delete", methods=["POST"])
def delete_target():
    global _active_target_key
    key = request.form.get("key")
    new_list = [t for t in _TARGETS if t["key"] != key]
    _TARGETS.clear()
    _TARGETS.extend(new_list)
    _save_targets(_TARGETS)
    if _active_target_key == key:
        _active_target_key = _TARGETS[0]["key"] if _TARGETS else ""
        if _TARGETS:
            _apply_active_target_env(_TARGETS[0])
        _save_active_target_key(_active_target_key)
    return redirect("/targets")


@app.route("/targets/update/<key>", methods=["POST"])
def update_target(key):
    target = next((t for t in _TARGETS if t["key"] == key), None)
    if not target:
        return redirect("/targets")
    target["login_url"] = request.form.get("login_url", "").strip()
    target["login_id"] = request.form.get("login_id", "").strip()
    target["login_password"] = request.form.get("login_password", "").strip()
    target["login_id_2"] = request.form.get("login_id_2", "").strip()
    target["login_password_2"] = request.form.get("login_password_2", "").strip()
    target["admin_id"] = request.form.get("admin_id", "").strip()
    target["admin_password"] = request.form.get("admin_password", "").strip()
    target["login_fail_indicator"] = request.form.get("login_fail_indicator", "").strip()
    _save_targets(_TARGETS)
    if target["key"] == _active_target_key:
        _apply_active_target_env(target)
    return redirect(f"/targets?saved=1&open={key}")


@app.route("/settings")
def settings_page():
    return redirect("/targets")


@app.route("/api/status")
def api_status():
    return jsonify({
        "running": _running_task is not None,
        "task":    _running_task or "",
        "run_id":  _current_run_id or "",
    })


@app.route("/runs")
def runs_page():
    return render_template("runs.html", runs=_list_runs(), current_run=_current_run_id)


@app.route("/runs/new", methods=["POST"])
def new_run():
    global _current_run_id
    _current_run_id = _create_run("main")
    return redirect("/")


@app.route("/runs/<run_id>")
def run_detail(run_id):
    run_dir = os.path.join(RUNS_DIR, run_id)
    if not os.path.isdir(run_dir):
        return "존재하지 않는 런입니다.", 404

    ts = _run_created_label(run_id)

    files = set(os.listdir(run_dir))
    run_type = _infer_run_type(run_id)

    step_timing: dict = {}
    if "timing.json" in files:
        try:
            with open(os.path.join(run_dir, "timing.json"), encoding="utf-8") as f:
                step_timing = json.load(f)
        except Exception:
            pass

    findings, xss_cnt, sqli_cnt, bac_cnt, misconfig_cnt = [], 0, 0, 0, 0
    if "findings.json" in files:
        try:
            findings = load_json(os.path.join(run_dir, "findings.json"), [])
            xss_cnt      = sum(1 for fi in findings if fi.get("module") == "xss")
            sqli_cnt     = sum(1 for fi in findings if fi.get("module") == "sqli")
            bac_cnt      = sum(1 for fi in findings if fi.get("module") == "bac")
            misconfig_cnt = sum(1 for fi in findings if fi.get("module") == "misconfig")
        except Exception:
            pass
    if "bac_findings.json" in files:
        findings.extend(load_json(os.path.join(run_dir, "bac_findings.json"), []))
    xss_cnt = sum(1 for fi in findings if fi.get("module") == "xss")
    sqli_cnt = sum(1 for fi in findings if fi.get("module") == "sqli")
    bac_cnt = sum(1 for fi in findings if fi.get("module") == "bac")

    exec_results, exec_ok, exec_timeout, exec_err = [], 0, 0, 0
    if "execution_results.json" in files:
        try:
            exec_results = load_json(os.path.join(run_dir, "execution_results.json"), [])
            exec_ok      = sum(1 for r in exec_results if r.get("error") is None)
            exec_timeout = sum(1 for r in exec_results if r.get("error") == "timeout")
            exec_err     = sum(1 for r in exec_results if r.get("error") and r.get("error") != "timeout")
        except Exception:
            pass
    if "bac_vertical_results.json" in files:
        exec_results.extend(load_json(os.path.join(run_dir, "bac_vertical_results.json"), []))
    exec_ok = sum(1 for r in exec_results if r.get("error") is None)
    exec_timeout = sum(1 for r in exec_results if r.get("error") == "timeout")
    exec_err = sum(1 for r in exec_results if r.get("error") and r.get("error") != "timeout")

    url_groups = _group_findings_by_url(findings)

    return render_template(
        "run_detail.html",
        run_id=run_id,
        ts=ts,
        run_type=run_type,
        is_current=(run_id == _current_run_id),
        has_crawl="crawl_result.json" in files,
        has_targets="targets.json" in files,
        has_probe="probe_tasks.json" in files or "bac_vertical_tasks.json" in files,
        has_exec="execution_results.json" in files or "bac_vertical_results.json" in files,
        has_findings="findings.json" in files or "bac_findings.json" in files,
        findings=findings,
        url_groups=url_groups,
        xss_cnt=xss_cnt,
        sqli_cnt=sqli_cnt,
        bac_cnt=bac_cnt,
        misconfig_cnt=misconfig_cnt,
        exec_results=exec_results,
        exec_total=len(exec_results),
        exec_ok=exec_ok,
        exec_timeout=exec_timeout,
        exec_err=exec_err,
        step_timing=step_timing,
        has_log="scan.log" in files,
        current_run=_current_run_id,
    )


@app.route("/runs/set/<run_id>", methods=["POST"])
def set_run(run_id):
    global _current_run_id
    if os.path.isdir(os.path.join(RUNS_DIR, run_id)):
        _current_run_id = run_id
    return redirect(f"/runs/{run_id}")


@app.route("/runs/delete/<run_id>", methods=["POST"])
def delete_run(run_id):
    global _current_run_id
    run_dir = os.path.join(RUNS_DIR, run_id)
    if os.path.isdir(run_dir) and _is_run_id(run_id):
        shutil.rmtree(run_dir)
        if _current_run_id == run_id:
            _init_run()
    return redirect("/runs")


@app.route("/runs/<run_id>/report.pdf")
def download_report(run_id):
    run_dir = os.path.join(RUNS_DIR, run_id)
    if not os.path.isdir(run_dir):
        return "Run not found", 404

    pdf_bytes = report_gen.generate(run_id, run_dir)
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"LADS_{run_id}.pdf",
    )


@app.route("/runs/<run_id>/scan.log")
def download_scan_log(run_id):
    from flask import send_file
    log_path = os.path.join(RUNS_DIR, run_id, "scan.log")
    if not os.path.exists(log_path):
        return "로그 파일이 없습니다.", 404
    return send_file(log_path, mimetype="text/plain", as_attachment=True, download_name=f"LADS_{run_id}.log")


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    _init_run()
    print("LADS dashboard: http://localhost:5000")
    _dev = os.getenv("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=_dev,
        use_reloader=True,
        threaded=True,
    )
