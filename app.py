import importlib
import os
import re
import subprocess
import sys
import time
import hashlib
import uuid
from datetime import datetime


# ── 의존성 자동 설치 ──────────────────────────────────────────────
_DEPS = {
    "flask":         "flask",
    "python-dotenv": "dotenv",
    "requests":      "requests",
    "beautifulsoup4":"bs4",
    "lxml":          "lxml",
    "openai":        "openai",
}

for _pkg, _mod in _DEPS.items():
    try:
        importlib.import_module(_mod)
    except ImportError:
        print(f"[INSTALL] {_pkg} 설치 중...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", _pkg, "-q"])
del _pkg, _mod


import json
import queue
import threading
from pathlib import Path

from flask import Flask, Response, render_template_string, request
from dotenv import load_dotenv

load_dotenv()


# ── 설정 ─────────────────────────────────────────────────────────
BASE_URL          = os.getenv("TARGET_URL",        "http://34.68.27.120:8081")
CMS_NAME          = "Gnuboard5 5.3.2.8"
CRAWL_RESULT_FILE = os.getenv("CRAWL_RESULT",      "crawl_result.json")
TARGETS_FILE      = os.getenv("TARGETS_FILE",      "targets.json")
PAYLOADS_FILE     = os.getenv("PAYLOADS_FILE",     "results/payloads_llm.json")
SCAN_RESULTS_FILE = os.getenv("SCAN_RESULTS_FILE", "results/scan_results_llm.json")
PAYLOADS_META_FILE = os.getenv("PAYLOADS_META_FILE", "results/payloads_llm_meta.json")
FUZZ_TASKS_FILE    = os.getenv("FUZZ_TASKS_FILE",   "fuzz_tasks.json")
EXEC_RESULTS_FILE  = os.getenv("EXEC_RESULTS_FILE", "execution_results.json")
FINDINGS_FILE      = os.getenv("FINDINGS_FILE",     "results/findings.json")

app = Flask(__name__)
_task_lock    = threading.Lock()
_thread_local = threading.local()


# #region agent log
_DBG_LOG_PATH = Path(__file__).with_name("debug-3194ca.log")
_DBG_BUILD_ID = os.getenv("LADS_BUILD_ID") or datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]


def _dbg(hypothesis_id: str, message: str, data: dict | None = None) -> None:
    try:
        payload = {
            "sessionId": "3194ca",
            "runId": "pre-fix",
            "hypothesisId": hypothesis_id,
            "location": "app.py",
            "message": message,
            "data": data or {},
            "timestamp": int(time.time() * 1000),
        }
        with _DBG_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _tmpl_fingerprint() -> str:
    try:
        s = (_COMMON_HEAD + _MAIN_HTML + _RESULTS_HTML + _EXEC_HTML).encode("utf-8", errors="ignore")
        return hashlib.sha256(s).hexdigest()[:12]
    except Exception:
        return "unknown"


_dbg(
    "H1",
    "startup",
    {
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "file": str(Path(__file__).resolve()),
        "mtime": int(Path(__file__).stat().st_mtime),
        "buildId": _DBG_BUILD_ID,
    },
)
# #endregion agent log


# ── stdout 라우팅 스트림 ──────────────────────────────────────────
class _RoutingStream:
    def __init__(self, original):
        self._orig = original

    def write(self, text):
        q = getattr(_thread_local, "log_queue", None)
        if q is not None:
            stripped = text.rstrip("\n")
            if stripped:
                q.put(stripped)
        else:
            self._orig.write(text)

    def flush(self):
        self._orig.flush()

    def __getattr__(self, name):
        return getattr(self._orig, name)


sys.stdout = _RoutingStream(sys.__stdout__)


# ── 태스크 함수 ───────────────────────────────────────────────────

def _task_crawl():
    from crawler import Crawler
    from target_builder import build_targets, print_summary

    print(f"크롤링 시작: {BASE_URL}")
    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save(CRAWL_RESULT_FILE)
    crawler.summary()

    print(f"타겟 구성 시작: {CRAWL_RESULT_FILE}")
    with open(CRAWL_RESULT_FILE, encoding="utf-8") as f:
        pages = json.load(f)
    targets = build_targets(pages)

    os.makedirs("results", exist_ok=True)
    with open(TARGETS_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"타겟 구성 완료: {TARGETS_FILE} ({len(targets)}개)")
    print_summary(targets)


def _task_payload():
    from payload.generate_payloads import run as generate_run

    os.makedirs("results", exist_ok=True)
    print(f"LLM 페이로드 생성 시작 (출력: {PAYLOADS_FILE})")
    generate_run(out_file=PAYLOADS_FILE)


def _task_scan():
    import scanner

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음. 페이로드를 먼저 생성하세요.")
        return

    os.makedirs("results", exist_ok=True)

    old_argv = sys.argv[:]
    argv_list = ["scanner.py", "--payloads", PAYLOADS_FILE, "--out", SCAN_RESULTS_FILE]
    if os.path.exists(TARGETS_FILE):
        argv_list += ["--targets", TARGETS_FILE]

    sys.argv = argv_list
    try:
        scanner.main()
    except SystemExit as e:
        if e.code and e.code != 0:
            print(f"[ERROR] 스캐너 종료: exit code {e.code}")
    finally:
        sys.argv = old_argv


def _task_fuzz():
    from fuzzer.fuzzing_strategy import build_tasks

    if not os.path.exists(PAYLOADS_FILE):
        print(f"[ERROR] {PAYLOADS_FILE} 없음.")
        print(f"        페이로드 생성(② LLM 페이로드 생성)을 먼저 실행하세요.")
        return

    if not os.path.exists(PAYLOADS_META_FILE):
        print(f"[WARN] {PAYLOADS_META_FILE} 없음. generate_payloads.py가 meta를 저장하도록 수정되어야 합니다.")
        return

    with open(PAYLOADS_META_FILE, encoding="utf-8") as f:
        points_meta = json.load(f)

    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        payloads = json.load(f)

    targets = None
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, encoding="utf-8") as f:
            targets = json.load(f)

    print(f"meta={len(points_meta)} payload_points={len(payloads)}")
    tasks = build_tasks(points_meta, payloads, targets)

    with open(FUZZ_TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

    replace_ = sum(1 for t in tasks if t.get("inject_mode") == "replace")
    append_  = sum(1 for t in tasks if t.get("inject_mode") == "append")
    print(f"완료: {len(tasks)} 태스크 → {FUZZ_TASKS_FILE}")
    print(f"         mode  → replace: {replace_}, append: {append_}")


def _task_execute():
    """: Executor"""
    from fuzzer.executor import execute

    if not os.path.exists(FUZZ_TASKS_FILE):
        print(f"[ERROR] {FUZZ_TASKS_FILE} 없음.  전략 수립을 먼저 실행하세요.")
        return

    with open(FUZZ_TASKS_FILE, encoding="utf-8") as f:
        tasks = json.load(f)

    print(f"{len(tasks)} 태스크 실행 시작")
    results = execute(tasks, timeout=10, delay=0.0, output_file=EXEC_RESULTS_FILE)

    ok      = sum(1 for r in results if r["error"] is None)
    timeout = sum(1 for r in results if r["error"] == "timeout")
    err     = sum(1 for r in results if r["error"] and r["error"] != "timeout")
    print(f"완료: 성공 {ok} / 타임아웃 {timeout} / 오류 {err} → {EXEC_RESULTS_FILE}")


def _task_validate():
    """Step 8.5: Validator - 응답 분석 → 취약점 판정"""
    from fuzzer.validator import run as validate_run

    if not os.path.exists(EXEC_RESULTS_FILE):
        print(f"[ERROR] {EXEC_RESULTS_FILE} 없음. Step 8 실행을 먼저 하세요.")
        return

    print(f"[Validator] {EXEC_RESULTS_FILE} 분석 중...")
    findings = validate_run(input_file=EXEC_RESULTS_FILE, output_file=FINDINGS_FILE)

    xss_cnt  = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sqli" in (f.get("vuln_type") or "").lower() or "sql" in (f.get("vuln_type") or "").lower())

    print(f"[Validator] 완료: 취약점 {len(findings)}개 발견 → {FINDINGS_FILE}")
    print(f"           XSS: {xss_cnt}개  /  SQLi: {sqli_cnt}개")
    for f in findings:
        print(f"  [{f['vuln_type']:20s}] {f['point']} | {f['payload'][:50]} | {f['evidence']}")


def _task_all(skip_crawl: bool = False, skip_payload: bool = False):
    if skip_crawl:
        print(f"[건너뜀] 크롤링 — {CRAWL_RESULT_FILE} 재사용")
    else:
        _task_crawl()

    if skip_payload:
        print(f"[건너뜀] 페이로드 생성 — {PAYLOADS_FILE} 재사용")
    else:
        _task_payload()

    _task_scan()


_TASK_FUNCS = {
    "crawl"   : _task_crawl,
    "payload" : _task_payload,
    "scan"    : _task_scan,
    "fuzz"    : _task_fuzz,
    "execute" : _task_execute,
    "validate": _task_validate,
    "all"     : _task_all,
}

_TASK_LABELS = {
    "crawl"   : "크롤링 + 타겟 구성",
    "payload" : "LLM 페이로드 생성",
    "scan"    : "스캔 실행",
    "fuzz"    : " · 전략 수립",
    "execute" : " · 실행",
    "validate": " · 취약점 판정",
    "all"     : "전체 파이프라인",
}


# ── SSE 라우트 ────────────────────────────────────────────────────

@app.route("/stream/<task>")
def stream_task(task):
    if task not in _TASK_FUNCS:
        return "알 수 없는 태스크", 404

    skip_crawl   = request.args.get("skip_crawl")   == "1"
    skip_payload = request.args.get("skip_payload") == "1"

    q = queue.Queue()

    def run_in_thread():
        acquired = _task_lock.acquire(blocking=False)
        if not acquired:
            q.put("[WARN] 다른 태스크가 실행 중입니다. 완료 후 다시 시도하세요.")
            q.put(None)
            return
        _thread_local.log_queue = q
        try:
            if task == "all":
                _task_all(skip_crawl=skip_crawl, skip_payload=skip_payload)
            else:
                _TASK_FUNCS[task]()
        except Exception as exc:
            q.put(f"[ERROR] {type(exc).__name__}: {exc}")
        finally:
            _thread_local.log_queue = None
            _task_lock.release()
            q.put(None)

    threading.Thread(target=run_in_thread, daemon=True).start()

    def generate():
        label = _TASK_LABELS.get(task, task)
        yield f"data: [{label}] 시작\n\n"
        while True:
            try:
                msg = q.get(timeout=2)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if msg is None:
                yield f"data: [{label}] 완료\n\n"
                yield "data: __DONE__\n\n"
                break
            safe = msg.replace("\n", " ")
            yield f"data: {safe}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── 상태 헬퍼 ─────────────────────────────────────────────────────

def _get_file_status():
    return [
        ("crawl_result.json",      os.path.exists(CRAWL_RESULT_FILE)),
        ("targets.json",           os.path.exists(TARGETS_FILE)),
        ("payloads_llm.json",      os.path.exists(PAYLOADS_FILE)),
        ("scan_results_llm.json",  os.path.exists(SCAN_RESULTS_FILE)),
        ("fuzz_tasks.json",        os.path.exists(FUZZ_TASKS_FILE)),
        ("execution_results.json", os.path.exists(EXEC_RESULTS_FILE)),
    ]


def _get_quick_summary():
    if not os.path.exists(SCAN_RESULTS_FILE):
        return None
    try:
        with open(SCAN_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
        total = len(results)
        vulns = sum(1 for r in results if r.get("vulnerable"))
        return {"total": total, "vulns": vulns, "rate": vulns / max(total, 1) * 100}
    except Exception:
        return None


def _get_exec_summary():
    if not os.path.exists(EXEC_RESULTS_FILE):
        return None
    try:
        with open(EXEC_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
        total   = len(results)
        ok      = sum(1 for r in results if r.get("error") is None)
        timeout = sum(1 for r in results if r.get("error") == "timeout")
        return {"total": total, "ok": ok, "timeout": timeout}
    except Exception:
        return None


# ── HTML 템플릿 ───────────────────────────────────────────────────

_COMMON_HEAD = """\
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <style>
    body         { background:#fff; color:#111; }
    .navbar      { background:#fff !important; border-bottom:1px solid #e5e7eb; }
    .card        { background:#fff; border:1px solid #e5e7eb; }
    .card-header { background:#f8fafc; border-bottom:1px solid #e5e7eb; color:#111; }
    #log-area {
      background:#fff; color:#111;
      font-family:'Courier New',monospace;
      font-size:.82rem;
      height:420px; overflow-y:auto;
      padding:12px; white-space:pre-wrap; word-break:break-all;
    }
    .badge-ok   { background:#111; }
    .badge-none { background:#6b7280; }
    .stat-num   { font-size:2rem; font-weight:700; }
    .vuln-row td  { background:#f3f4f6!important; }
    .safe-row td  { background:#fff!important; }
    table        { color:#111; }
    th           { color:#111; font-weight:600; }
    a            { color:#111; text-decoration:underline; }
    .form-check-label { color:#111; font-size:.85rem; }

    /* Bootstrap 색상 -> 흑백 */
    .text-info, .text-danger, .text-warning, .text-success, .text-secondary { color:#111 !important; }
    .bg-info, .bg-danger, .bg-warning, .bg-success, .bg-secondary { background:#111 !important; color:#fff !important; }
    .btn-danger { background:#111; border-color:#111; }
  </style>"""


_MAIN_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <title>LADS </title>
""" + _COMMON_HEAD + """
</head>
<body>

<nav class="navbar navbar-light mb-4 px-3">
  <div class="container-fluid">
    <span class="navbar-brand fw-bold fs-4 me-3">LADS</span>
  </div>
</nav>

<div class="container">
  {% if false %}

  <!-- 결과 요약 -->
  {% endif %}
  {% if summary or exec_summary %}
  <div class="card mb-3">
    <div class="card-header fw-semibold">결과 요약</div>
    <div class="card-body">
      <div class="row text-center">
        {% if summary %}
        <div class="col-4">
          <div class="stat-num text-info">{{ summary.total }}</div>
          <div class="text-secondary small">스캔 총 테스트</div>
        </div>
        <div class="col-4">
          <div class="stat-num text-danger">{{ summary.vulns }}</div>
          <div class="text-secondary small">취약 건수</div>
        </div>
        <div class="col-4">
          <div class="stat-num text-warning">{{ "%.1f"|format(summary.rate) }}%</div>
          <div class="text-secondary small">취약률</div>
        </div>
        {% endif %}
        {% if exec_summary %}
        <div class="col-12 mt-2 pt-2" style="border-top:1px solid #e5e7eb">
          <span class="text-info me-3">총 {{ exec_summary.total }}건</span>
          <span class="text-success me-3">성공 {{ exec_summary.ok }}</span>
          <span class="text-warning">타임아웃 {{ exec_summary.timeout }}</span>
        </div>
        {% endif %}
      </div>
      
    </div>
  </div>
  {% endif %}

  <!-- 기존 파이프라인 -->
  <div class="card mb-3">
    <div class="card-header fw-semibold">기존 파이프라인</div>
    <div class="card-body">
      <div class="d-flex flex-wrap gap-2 mb-3">
        <button class="btn btn-outline-primary" onclick="runTask('crawl')">크롤링 + 타겟 구성</button>
        <button class="btn btn-outline-warning" onclick="runTask('payload')"> LLM 페이로드 생성</button>
        <button class="btn btn-outline-success" onclick="runTask('scan')">스캔 실행</button>
      </div>
      <hr style="border-color:#e5e7eb">
      <div class="d-flex align-items-center gap-3 flex-wrap">
        <button class="btn btn-danger" onclick="runTaskAll()">전체 실행</button>
        <a class="btn btn-outline-dark" href="/results">스캔 결과 보기</a>
        <a class="btn btn-outline-dark" href="/exec_results">실행 결과 보기</a>
      </div>
    </div>
  </div>


  <!-- 실행 로그 -->
  <div class="card mb-4" id="log-card" style="display:none">
    <div class="card-header d-flex justify-content-between align-items-center">
      <span class="fw-semibold" id="log-title">실행 로그</span>
      <span id="log-badge" class="badge bg-warning text-dark">실행 중</span>
    </div>
    <div class="card-body p-0">
      <div id="log-area"></div>
    </div>
  </div>

</div>

<script>
var _es = null;

function runTask(task) {
  _startStream('/stream/' + task);
}

function runTaskAll() {
  _startStream('/stream/all');
}

var _labels = {
  crawl:   '크롤링 + 타겟 구성',
  payload: 'LLM 페이로드 생성',
  scan:    '스캔 실행',
  all:     '전체 파이프라인'
};

function _startStream(url) {
  if (_es) { _es.close(); _es = null; }

  var logCard  = document.getElementById('log-card');
  var logArea  = document.getElementById('log-area');
  var logTitle = document.getElementById('log-title');
  var logBadge = document.getElementById('log-badge');

  var taskName = url.split('/stream/')[1].split('?')[0];
  logCard.style.display = 'block';
  logTitle.textContent  = (_labels[taskName] || taskName) + ' 로그';
  logBadge.textContent  = '실행 중';
  logBadge.className    = 'badge bg-warning text-dark';
  logArea.textContent   = '';

  document.querySelectorAll('button').forEach(function(b) { b.disabled = true; });
  logCard.scrollIntoView({ behavior: 'smooth' });

  _es = new EventSource(url);

  _es.onmessage = function(e) {
    if (e.data === '__DONE__') {
      _es.close(); _es = null;
      logBadge.textContent = '완료';
      logBadge.className   = 'badge bg-success';
      document.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
      setTimeout(function() { location.reload(); }, 2000);
      return;
    }
    var line = document.createElement('div');
    if      (e.data.indexOf('[ERROR]') !== -1) line.style.color = '#111';
    else if (e.data.indexOf('[WARN]')  !== -1) line.style.color = '#111';
    else if (e.data.indexOf('완료')    !== -1) line.style.color = '#111';
    else if (e.data.indexOf('')  !== -1) line.style.color = '#111';
    else if (e.data.indexOf('')  !== -1) line.style.color = '#111';
    line.textContent = e.data;
    logArea.appendChild(line);
    logArea.scrollTop = logArea.scrollHeight;
  };

  _es.onerror = function() {
    if (_es) { _es.close(); _es = null; }
    logBadge.textContent = '오류';
    logBadge.className   = 'badge bg-danger';
    document.querySelectorAll('button').forEach(function(b) { b.disabled = false; });
    var line = document.createElement('div');
    line.style.color = '#111';
    line.textContent = '[연결 오류 - 서버를 확인하세요]';
    logArea.appendChild(line);
  };
}
</script>
</body>
</html>"""


_RESULTS_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <title>LADS - 스캔 결과</title>
""" + _COMMON_HEAD + """
</head>
<body>

<nav class="navbar navbar-light mb-4 px-3">
  <div class="container-fluid">
    <span class="navbar-brand fw-bold fs-4 me-3">LADS</span>
    <span class="text-secondary me-auto">스캔 결과</span>
    <a href="/" class="btn btn-outline-dark btn-sm">대시보드</a>
  </div>
</nav>

<div class="container-fluid px-4">
{% if not results %}
  <div class="alert" style="background:#fff;border:1px solid #e5e7eb;color:#111;">
    스캔 결과가 없습니다. 대시보드에서 스캔을 실행하세요.
  </div>
{% else %}
  <div class="card mb-4">
    <div class="card-body">
      <div class="row text-center">
        <div class="col-4">
          <div class="stat-num text-info">{{ total }}</div>
          <div class="text-secondary small">총 테스트</div>
        </div>
        <div class="col-4">
          <div class="stat-num text-danger">{{ n_vuln }}</div>
          <div class="text-secondary small">취약 건수</div>
        </div>
        <div class="col-4">
          <div class="stat-num text-warning">{{ "%.1f"|format(rate) }}%</div>
          <div class="text-secondary small">취약률</div>
        </div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-header fw-semibold">상세 결과</div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-borderless mb-0" style="font-size:.82rem;">
          <thead>
            <tr style="border-bottom:1px solid #e5e7eb;">
              <th>포인트</th><th>취약점 유형</th><th>페이로드</th>
              <th>상태코드</th><th>응답 크기</th><th>응답 시간</th><th>판정</th>
            </tr>
          </thead>
          <tbody>
            {% for r in results %}
            <tr class="{% if r.vulnerable %}vuln-row{% else %}safe-row{% endif %}"
                style="border-bottom:1px solid #e5e7eb;">
              <td style="max-width:160px;" class="text-break">{{ r.point }}</td>
              <td>{{ r.vuln_type }}</td>
              <td style="max-width:260px;" class="text-break font-monospace">{{ r.payload }}</td>
              <td>{% if r.response %}{{ r.response.status }}{% else %}-{% endif %}</td>
              <td>{% if r.response %}{{ r.response.length }}{% else %}-{% endif %}</td>
              <td>
                {% if r.response and r.response.elapsed is not none %}
                  {{ "%.2f"|format(r.response.elapsed) }}s
                {% else %}-{% endif %}
              </td>
              <td>
                {% if r.vulnerable %}<span class="badge bg-secondary">취약</span>
                {% else %}<span class="badge bg-secondary">안전</span>{% endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
{% endif %}
</div>
</body>
</html>"""


_EXEC_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <title>LADS - 실행 결과 ()</title>
""" + _COMMON_HEAD + """
</head>
<body>

<nav class="navbar navbar-light mb-4 px-3">
  <div class="container-fluid">
    <span class="navbar-brand fw-bold fs-4 me-3">LADS</span>
    <span class="text-secondary me-auto"> · 실행 결과</span>
    <a href="/" class="btn btn-outline-dark btn-sm">대시보드</a>
  </div>
</nav>

<div class="container-fluid px-4">
{% if not results %}
  <div class="alert" style="background:#fff;border:1px solid #e5e7eb;color:#111;">
    실행 결과가 없습니다. 대시보드에서  · 실행을 먼저 실행하세요.
  </div>
{% else %}
  <div class="card mb-4">
    <div class="card-body">
      <div class="row text-center">
        <div class="col-3">
          <div class="stat-num text-info">{{ total }}</div>
          <div class="text-secondary small">총 요청</div>
        </div>
        <div class="col-3">
          <div class="stat-num text-success">{{ ok }}</div>
          <div class="text-secondary small">성공</div>
        </div>
        <div class="col-3">
          <div class="stat-num text-warning">{{ timeout }}</div>
          <div class="text-secondary small">타임아웃</div>
        </div>
        <div class="col-3">
          <div class="stat-num text-danger">{{ err }}</div>
          <div class="text-secondary small">오류</div>
        </div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-header fw-semibold">실행 상세 ( Executor 출력)</div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-borderless mb-0" style="font-size:.80rem;">
          <thead>
            <tr style="border-bottom:1px solid #e5e7eb;">
              <th>task_id</th><th>파라미터</th><th>scope</th><th>mode</th>
              <th>위치</th><th>취약점 유형</th><th>페이로드</th>
              <th>상태코드</th><th>응답길이</th><th>응답시간</th><th>오류</th>
            </tr>
          </thead>
          <tbody>
            {% for r in results %}
            <tr style="border-bottom:1px solid #e5e7eb;
                       {% if r.error %}background:#f3f4f6{% endif %}">
              <td class="font-monospace text-secondary">{{ r.task_id }}</td>
              <td class="font-monospace">{{ r.inject_param }}</td>
              <td>
                <span class="badge {% if r.inject_scope == 'multiple' %}bg-warning text-dark{% else %}bg-secondary{% endif %}">
                  {{ r.inject_scope }}</span>
              </td>
              <td>
                <span class="badge {% if r.inject_mode == 'append' %}bg-info text-dark{% else %}bg-secondary{% endif %}">
                  {{ r.inject_mode }}</span>
              </td>
              <td>{{ r.inject_location }}</td>
              <td>{{ r.vuln_type }}</td>
              <td style="max-width:200px;" class="text-break font-monospace">{{ r.payload }}</td>
              <td>{{ r.status_code or '-' }}</td>
              <td>{{ r.response_length or '-' }}</td>
              <td>{% if r.response_time %}{{ "%.3f"|format(r.response_time) }}s{% else %}-{% endif %}</td>
              <td style="color:#111;">{{ r.error or '' }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
{% endif %}
</div>
</body>
</html>"""


# ── 라우트 ────────────────────────────────────────────────────────

_MAIN_HTML = _MAIN_HTML.replace("  {% if false %}", "")
_MAIN_HTML = _MAIN_HTML.replace("  {% endif %}\n  {% if summary or exec_summary %}", "  {% if summary or exec_summary %}")
_MAIN_HTML = re.sub(
    r'\s*<div class="card mb-3">\s*<div class="card-header fw-semibold">.*?</div>\s*'
    r'<div class="card-body">\s*<div class="row mb-1">\s*'
    r'<div class="col-sm-2 text-secondary">CMS</div>.*?</div>\s*</div>\s*</div>',
    "",
    _MAIN_HTML,
    count=1,
    flags=re.S,
)
_MAIN_HTML = re.sub(
    r'\s*<div class="card mb-3">\s*<div class="card-header fw-semibold">.*?</div>\s*'
    r'<div class="card-body">\s*<div class="row g-2">\s*'
    r'{% for label, ok in file_status %}.*?{% endfor %}\s*</div>\s*</div>\s*</div>',
    "",
    _MAIN_HTML,
    count=1,
    flags=re.S,
)


@app.route("/")
def index():
    # #region agent log
    _dbg(
        "H2",
        "GET /",
        {
            "pid": os.getpid(),
            "buildId": _DBG_BUILD_ID,
            "tmplFp": _tmpl_fingerprint(),
            "ua": (request.headers.get("User-Agent") or "")[:120],
            "addr": request.remote_addr,
        },
    )
    # #endregion agent log
    return render_template_string(
        _MAIN_HTML,
        cms_name     = CMS_NAME,
        base_url     = BASE_URL,
        file_status  = _get_file_status(),
        summary      = _get_quick_summary(),
        exec_summary = _get_exec_summary(),
    )


@app.route("/__debug_build")
def __debug_build():
    # #region agent log
    _dbg("H3", "GET /__debug_build", {"pid": os.getpid(), "buildId": _DBG_BUILD_ID, "tmplFp": _tmpl_fingerprint()})
    # #endregion agent log
    return {
        "pid": os.getpid(),
        "buildId": _DBG_BUILD_ID,
        "tmplFp": _tmpl_fingerprint(),
        "file": str(Path(__file__).resolve()),
    }


@app.route("/results")
def results_page():
    if not os.path.exists(SCAN_RESULTS_FILE):
        return render_template_string(_RESULTS_HTML, results=None, total=0, n_vuln=0, rate=0.0)
    try:
        with open(SCAN_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500

    total  = len(results)
    n_vuln = sum(1 for r in results if r.get("vulnerable"))
    rate   = n_vuln / max(total, 1) * 100
    return render_template_string(_RESULTS_HTML, results=results, total=total, n_vuln=n_vuln, rate=rate)


@app.route("/exec_results")
def exec_results_page():
    if not os.path.exists(EXEC_RESULTS_FILE):
        return render_template_string(_EXEC_HTML, results=None, total=0, ok=0, timeout=0, err=0)
    try:
        with open(EXEC_RESULTS_FILE, encoding="utf-8") as f:
            results = json.load(f)
    except Exception as exc:
        return f"결과 파일 읽기 오류: {exc}", 500

    total   = len(results)
    ok      = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err     = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    return render_template_string(_EXEC_HTML, results=results, total=total, ok=ok, timeout=timeout, err=err)


# ── 서버 시작 ─────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    print(f"LADS 대시보드 시작: http://localhost:5000")
    print(f"타겟: {BASE_URL}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
