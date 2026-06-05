from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime

from fpdf import FPDF  # pyright: ignore[reportMissingModuleSource]


VULN_LABELS = {
    "xss":       "XSS",
    "sqli":      "SQLi",
    "sql":       "SQLi",
    "bac":       "BAC",
    "misconfig": "Misconfig",
}

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "": 3}


def _vuln_label(module: str) -> str:
    vt = (module or "").lower()
    for key, label in VULN_LABELS.items():
        if key in vt:
            return label
    return (module or "").upper()


def _severity(confidence: str) -> str:
    c = (confidence or "").lower()
    if c == "high":   return "HIGH"
    if c == "medium": return "MEDIUM"
    return "LOW"


def _clean(val) -> str:
    return str(val or "").replace("\t", " ").replace("\n", " ").replace("\r", "")


def _group_findings(findings: list[dict]) -> list[dict]:
    """
    payload 기반(XSS/SQLi/BAC): (module, category, url, param) 로 그룹핑
    misconfig: 개별 유지
    반환: 그룹 대표 dict + payload_count, payloads 필드 추가
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    misc_items: list[dict] = []

    for f in findings:
        mod = (f.get("module") or "").lower()
        if mod == "misconfig":
            misc_items.append(f)
        else:
            key = (
                f.get("module", ""),
                f.get("category", ""),
                f.get("url", ""),
                f.get("param", ""),
            )
            groups[key].append(f)

    result: list[dict] = []

    # 그룹핑된 항목 — confidence 높은 것을 대표로
    for key, items in groups.items():
        items.sort(key=lambda x: _SEVERITY_ORDER.get((x.get("confidence") or "").lower(), 3))
        rep = dict(items[0])
        rep["payload_count"] = len(items)
        rep["all_payloads"] = [_clean(i.get("payload", "")) for i in items if i.get("payload")]
        result.append(rep)

    # 심각도 → 모듈 순 정렬
    result.sort(key=lambda x: (
        _SEVERITY_ORDER.get((x.get("confidence") or "").lower(), 3),
        x.get("module", ""),
    ))

    # misconfig는 뒤에 붙임
    for m in misc_items:
        m["payload_count"] = 1
        m["all_payloads"] = []
        result.append(m)

    return result


def generate(run_id: str, run_dir: str) -> bytes:
    findings_path = os.path.join(run_dir, "findings.json")
    findings: list[dict] = []
    if os.path.exists(findings_path):
        with open(findings_path, encoding="utf-8") as f:
            findings = json.load(f)

    try:
        ts = datetime.strptime(run_id, "run_%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        parts = run_id.split("-")
        if len(parts) >= 4 and parts[0] == "run":
            try:
                ts = datetime.strptime(parts[2], "%Y%m%d").strftime("%Y-%m-%d")
            except Exception:
                ts = run_id
        else:
            ts = run_id

    xss_cnt       = sum(1 for f in findings if f.get("module") == "xss")
    sqli_cnt      = sum(1 for f in findings if f.get("module") == "sqli")
    bac_cnt       = sum(1 for f in findings if f.get("module") == "bac")
    misconfig_cnt = sum(1 for f in findings if f.get("module") == "misconfig")

    grouped = _group_findings(findings)

    # ── PDF 초기화 ────────────────────────────────────────────────
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    _FONT_PATH = r"C:\Windows\Fonts\malgun.ttf"
    if os.path.exists(_FONT_PATH):
        pdf.add_font("Malgun", fname=_FONT_PATH)
        pdf.add_font("Malgun", style="B", fname=_FONT_PATH)
        FN, FB = "Malgun", "Malgun"
    else:
        FN, FB = "Helvetica", "Helvetica"

    pdf.add_page()

    # ── 헤더 ─────────────────────────────────────────────────────
    pdf.set_font(FB, "B", 22)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 12, "LADS Vulnerability Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font(FN, "", 10)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, f"Run ID: {run_id}    Scanned: {ts}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    pdf.set_draw_color(200, 210, 220)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # ── Summary ───────────────────────────────────────────────────
    pdf.set_font(FB, "B", 13)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # 요약 카드 (raw count)
    summary_items = [
        ("Total Findings",   len(findings),    (9, 20, 38),      (238, 242, 247)),
        ("XSS",              xss_cnt,           (180, 90, 0),     (255, 243, 224)),
        ("SQLi",             sqli_cnt,          (186, 26, 26),    (255, 235, 235)),
        ("BAC",              bac_cnt,           (90, 30, 160),    (243, 232, 255)),
        ("Misconfig",        misconfig_cnt,     (20, 80, 180),    (224, 235, 255)),
    ]
    cw = 38
    for label, val, tc, fc in summary_items:
        pdf.set_fill_color(*fc)
        pdf.set_draw_color(220, 225, 230)
        pdf.rect(pdf.get_x(), pdf.get_y(), cw, 18, style="FD")
        y0 = pdf.get_y()
        x0 = pdf.get_x()
        pdf.set_font(FN, "", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.set_xy(x0, y0 + 1)
        pdf.cell(cw, 5, label, align="C")
        pdf.set_font(FB, "B", 14)
        pdf.set_text_color(*tc)
        pdf.set_xy(x0, y0 + 7)
        pdf.cell(cw, 8, str(val), align="C")
        pdf.set_xy(x0 + cw, y0)

    pdf.ln(22)

    # 그룹 수 안내
    if findings:
        vuln_groups = [g for g in grouped if g.get("module") != "misconfig"]
        misc_groups = [g for g in grouped if g.get("module") == "misconfig"]
        pdf.set_font(FN, "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 6,
            f"총 {len(findings)}개 탐지 결과 → {len(vuln_groups)}개 취약점 그룹 + {len(misc_groups)}개 설정 오류",
            new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    pdf.set_draw_color(200, 210, 220)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    if not findings:
        pdf.set_font(FN, "", 11)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "No vulnerabilities found.", new_x="LMARGIN", new_y="NEXT")
        return bytes(pdf.output())

    # ── Findings ──────────────────────────────────────────────────
    pdf.set_font(FB, "B", 13)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # 심각도 색상
    _sev_colors = {
        "HIGH":   (186, 26, 26),
        "MEDIUM": (160, 100, 0),
        "LOW":    (30, 100, 160),
    }
    _sev_bg = {
        "HIGH":   (255, 235, 235),
        "MEDIUM": (255, 243, 224),
        "LOW":    (224, 235, 255),
    }

    for i, f in enumerate(grouped, 1):
        if pdf.get_y() > 250:
            pdf.add_page()

        mod      = f.get("module", "")
        vtype    = _vuln_label(mod)
        category = f.get("category", "")
        conf     = f.get("confidence", "")
        sev      = _severity(conf)
        count    = f.get("payload_count", 1)
        tc       = _sev_colors.get(sev, (60, 60, 60))
        bg       = _sev_bg.get(sev,    (242, 244, 246))

        # 항목 헤더
        pdf.set_fill_color(*bg)
        pdf.set_draw_color(200, 210, 220)
        y_start = pdf.get_y()
        pdf.set_font(FB, "B", 11)
        pdf.set_text_color(9, 20, 38)
        pdf.cell(0, 9, f"  [{i}]  {vtype}  —  {category}", fill=True, new_x="LMARGIN", new_y="NEXT")

        # 심각도 + 페이로드 수 뱃지 (헤더 오른쪽)
        pdf.set_xy(155, y_start + 0.5)
        pdf.set_fill_color(*tc)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(FB, "B", 8)
        pdf.cell(22, 8, f" {sev} ", fill=True, align="C")
        if count > 1:
            pdf.set_fill_color(80, 80, 80)
            pdf.cell(15, 8, f" x{count} ", fill=True, align="C")
        pdf.set_xy(10, y_start + 9)

        # 세부 정보
        url   = _clean(f.get("url", ""))
        param = _clean(f.get("param", ""))
        payload = _clean(f.get("payload", ""))
        evidence = _clean(f.get("evidence", ""))

        rows = [("URL", url[:100] + ("..." if len(url) > 100 else ""))]
        if param:
            rows.append(("Param", param))
        if payload:
            label_payload = f"Payload (대표)" if count > 1 else "Payload"
            rows.append((label_payload, payload[:100] + ("..." if len(payload) > 100 else "")))
        rows.append(("Evidence", evidence[:110] + ("..." if len(evidence) > 110 else "")))

        # misconfig version_disclosure: CVE 목록
        extra = f.get("extra") or {}
        cves = extra.get("cves") or []

        pdf.set_text_color(60, 60, 60)
        for label, val in rows:
            pdf.set_font(FB, "B", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(26, 5.5, f"  {label}")
            pdf.set_font(FN, "", 9)
            pdf.set_text_color(40, 40, 40)
            pdf.cell(0, 5.5, val, new_x="LMARGIN", new_y="NEXT")

        # CVE 있으면 상위 3개 표시
        if cves:
            pdf.set_font(FB, "B", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(26, 5.5, "  CVEs")
            pdf.set_font(FN, "", 9)
            pdf.set_text_color(186, 26, 26)
            cve_str = "  ".join(
                f"{c.get('id','')} ({c.get('severity','')} {c.get('score','')})"
                for c in cves[:3]
            )
            pdf.cell(0, 5.5, cve_str[:110], new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)

    return bytes(pdf.output())
