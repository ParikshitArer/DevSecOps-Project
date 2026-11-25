#!/usr/bin/env python3
"""Build one readable HTML security report from DevSecOps scanner JSON output.

Inputs (all optional; missing files are shown as "not run"):
  gitleaks-report.json   gitleaks ... --report-format json
  bandit-report.json     bandit -f json
  semgrep-report.json    semgrep scan --json
  dependency-report.json pip-audit --format json
  trivy-report.json      trivy image --format json
  sbom.json              syft ... -o cyclonedx-json
  zap-report.json        zap report in JSON (optional)

Usage:
  python3 generate_report.py --out report.html --build 42 --commit a1b2c3d
  python3 generate_report.py --fail-on HIGH     # exit 1 if gate fails
"""
import argparse
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def load(path):
    if not os.path.exists(path):
        return "missing", None
    try:
        with open(path, encoding="utf-8") as f:
            txt = f.read().strip()
        return "ok", (json.loads(txt) if txt else None)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "invalid", None


def F(sev, title, where="", detail="", fix=""):
    return dict(sev=sev if sev in SEV else "INFO", title=title, where=where, detail=detail, fix=fix)


def p_gitleaks(d):
    return [F("CRITICAL", f"Secret found: {x.get('RuleID', 'unknown rule')}",
              f"{x.get('File', '?')}:{x.get('StartLine', '?')}",
              x.get("Description", ""), "Rotate the secret, then remove it from git history")
            for x in (d or [])]


def p_bandit(d):
    m = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return [F(m.get(x.get("issue_severity", ""), "INFO"),
              f"{x.get('test_id', '')} {x.get('test_name', '')}".strip(),
              f"{x.get('filename', '?')}:{x.get('line_number', '?')}",
              x.get("issue_text", ""), f"Confidence: {x.get('issue_confidence', 'n/a')}")
            for x in (d or {}).get("results", [])]


def p_semgrep(d):
    m = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    out = []
    for x in (d or {}).get("results", []):
        ex = x.get("extra", {})
        out.append(F(m.get(ex.get("severity", ""), "INFO"), x.get("check_id", "rule").split(".")[-1],
                     f"{x.get('path', '?')}:{x.get('start', {}).get('line', '?')}",
                     ex.get("message", ""), ex.get("fix", "")))
    return out


def p_pipaudit(d):
    deps = d.get("dependencies", []) if isinstance(d, dict) else (d or [])
    out = []
    for dep in deps:
        for v in dep.get("vulns", []):
            fixes = ", ".join(v.get("fix_versions", [])) or "no fix available"
            out.append(F("HIGH", f"{v.get('id', 'vuln')} in {dep.get('name')} {dep.get('version')}",
                         dep.get("name", ""), v.get("description", ""), f"Upgrade to: {fixes}"))
    return out


def p_trivy(d):
    m = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    out = []
    for r in (d or {}).get("Results", []) or []:
        for v in r.get("Vulnerabilities", []) or []:
            out.append(F(m.get(v.get("Severity", ""), "INFO"),
                         f"{v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion')}",
                         r.get("Target", ""), v.get("Title", ""),
                         f"Fixed in: {v['FixedVersion']}" if v.get("FixedVersion") else "No fix yet"))
    return out


def p_zap(d):
    m = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    out = []
    for s in (d or {}).get("site", []):
        for a in s.get("alerts", []):
            n = len(a.get("instances", []))
            out.append(F(m.get(str(a.get("riskcode", "0")), "INFO"), a.get("name", "alert"),
                         f"{n} instance(s)", html.unescape(a.get("desc", "")).replace("<p>", "").replace("</p>", " "),
                         html.unescape(a.get("solution", "")).replace("<p>", "").replace("</p>", " ")))
    return out


TOOLS = [
    ("gitleaks", "Secret scan", "Gitleaks", "gitleaks-report.json", p_gitleaks),
    ("bandit", "SAST", "Bandit", "bandit-report.json", p_bandit),
    ("semgrep", "SAST", "Semgrep", "semgrep-report.json", p_semgrep),
    ("pipaudit", "SCA", "pip-audit", "dependency-report.json", p_pipaudit),
    ("trivy", "Container scan", "Trivy", "trivy-report.json", p_trivy),
    ("zap", "DAST", "OWASP ZAP", "zap-report.json", p_zap),
]

CSS = """
:root{--bg:#fff;--card:#f7f6f2;--line:#e1dfd6;--ink:#262624;--mute:#6b6a64;--ok:#3b6d11;--okbg:#eaf3de;
--bad:#a32d2d;--badbg:#fcebeb;--warn:#854f0b;--warnbg:#faeeda;
--c-CRITICAL:#a32d2d;--c-HIGH:#d85a30;--c-MEDIUM:#ba7517;--c-LOW:#378add;--c-INFO:#888780}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b1a;--card:#262624;--line:#3a3a37;--ink:#ecebe6;--mute:#a3a29a;
--ok:#97c459;--okbg:#27500a;--bad:#f09595;--badbg:#501313;--warn:#fac775;--warnbg:#412402}}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.meta{color:var(--mute);font-size:13px}.meta span{margin-right:16px}
.verdict{border-radius:10px;padding:14px 18px;margin:18px 0;font-weight:600;font-size:16px}
.verdict small{display:block;font-weight:400;font-size:13px;margin-top:2px}
.pass{background:var(--okbg);color:var(--ok)}.fail{background:var(--badbg);color:var(--bad)}.warn{background:var(--warnbg);color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .t{font-weight:600}.card .c{color:var(--mute);font-size:12px}.card .n{font-size:30px;font-weight:600;margin:6px 0 4px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff;margin:0 4px 4px 0}
.pill.s-CRITICAL{background:var(--c-CRITICAL)}.pill.s-HIGH{background:var(--c-HIGH)}.pill.s-MEDIUM{background:var(--c-MEDIUM)}
.pill.s-LOW{background:var(--c-LOW)}.pill.s-INFO{background:var(--c-INFO)}
.state{font-size:12px;color:var(--mute)}.clean{color:var(--ok);font-weight:600;font-size:13px}
.bar{display:flex;height:22px;border-radius:6px;overflow:hidden;background:var(--line)}
.bar div{height:100%}.legend{margin-top:8px;font-size:13px;color:var(--mute)}.legend b{color:var(--ink)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 12px}
details{border:1px solid var(--line);border-radius:10px;margin:10px 0;background:var(--card)}
summary{cursor:pointer;padding:12px 16px;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}summary:before{content:"\\25B8";margin-right:8px;color:var(--mute)}
details[open] summary:before{content:"\\25BE"}summary .c{color:var(--mute);font-weight:400;font-size:13px;margin-left:8px}
.tw{overflow-x:auto;padding:0 16px 14px}table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mute);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}td.w{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
.empty{padding:0 16px 14px;color:var(--mute)}.foot{margin-top:28px;color:var(--mute);font-size:12px}
"""


def e(s, n=320):
    s = " ".join(str(s).split())
    return html.escape(s if len(s) <= n else s[: n - 1] + "…")


def pills(counter):
    return "".join(f'<span class="pill s-{s}">{counter[s]} {s.title()}</span>' for s in SEV if counter[s])


def build(args):
    results, total = [], Counter()
    for key, cat, name, path, parser in TOOLS:
        status, data = load(os.path.join(args.dir, path))
        items = parser(data) if status == "ok" else []
        items.sort(key=lambda x: SEV.index(x["sev"]))
        c = Counter(i["sev"] for i in items)
        total.update(c)
        linked = key == "zap" and status == "missing" and os.path.exists(os.path.join(args.dir, "zap-report.html"))
        results.append(dict(key=key, cat=cat, name=name, path=path, status=status, items=items, count=c, linked=linked))

    sstatus, sbom = load(os.path.join(args.dir, "sbom.json"))
    comps = (sbom or {}).get("components", []) if sstatus == "ok" else []

    gate_idx = SEV.index(args.fail_on)
    blocking = sum(total[s] for s in SEV[: gate_idx + 1])
    missing = [r["name"] + (" (HTML only, not counted)" if r["linked"] else "") for r in results if r["status"] != "ok"]
    if blocking:
        vclass, vtitle = "fail", f"Gate failed: {blocking} finding(s) at {args.fail_on.title()} or above"
    elif total["MEDIUM"] or missing:
        vclass, vtitle = "warn", "Gate passed with warnings"
    else:
        vclass, vtitle = "pass", "Gate passed: no blocking findings"
    vsub = f"Policy: block on {args.fail_on.title()} and above. "
    if missing:
        vsub += "Not run or unreadable: " + ", ".join(missing) + "."

    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Security report</title>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body><div class='wrap'>"]
    h.append("<h1>DevSecOps security report</h1><div class='meta'>"
             f"<span>Build #{e(args.build)}</span><span>Commit {e(args.commit)}</span>"
             f"<span>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</span></div>")
    h.append(f"<div class='verdict {vclass}'>{html.escape(vtitle)}<small>{html.escape(vsub)}</small></div>")

    h.append("<div class='grid'>")
    for r in results:
        if r["linked"]:
            body = "<div class='n'>–</div><div class='state'><a href='zap-report.html'>Open ZAP report</a></div>"
        elif r["status"] != "ok":
            body = f"<div class='n'>–</div><div class='state'>{'Not run' if r['status'] == 'missing' else 'Report unreadable'}</div>"
        elif not r["items"]:
            body = "<div class='n'>0</div><div class='clean'>Clean</div>"
        else:
            body = f"<div class='n'>{len(r['items'])}</div>{pills(r['count'])}"
        h.append(f"<div class='card'><div class='t'>{r['name']}</div><div class='c'>{r['cat']}</div>{body}</div>")
    h.append(f"<div class='card'><div class='t'>Syft</div><div class='c'>SBOM</div>"
             f"<div class='n'>{len(comps) if sstatus == 'ok' else '–'}</div>"
             f"<div class='state'>{'components inventoried' if sstatus == 'ok' else 'Not run'}</div></div></div>")

    allc = sum(total.values())
    h.append("<h2>Severity overview</h2>")
    if allc:
        h.append("<div class='bar'>" + "".join(
            f"<div style='width:{total[s] / allc * 100:.2f}%;background:var(--c-{s})' title='{s}: {total[s]}'></div>"
            for s in SEV if total[s]) + "</div><div class='legend'>" + "".join(
            f"<span class='dot' style='background:var(--c-{s})'></span>{s.title()} <b>{total[s]}</b>" for s in SEV) + "</div>")
    else:
        h.append("<div class='empty'>No findings across any scanner.</div>")

    h.append("<h2>Findings by tool</h2>")
    for r in results:
        op = " open" if r["items"] else ""
        h.append(f"<details{op}><summary>{r['name']}<span class='c'>{r['cat']} · {len(r['items'])} finding(s)</span></summary>")
        if r["linked"]:
            h.append("<div class='empty'><a href='zap-report.html'>Open zap-report.html</a>. "
                     "ZAP findings come as HTML here, so they are not counted in the totals above.</div>")
        elif r["status"] != "ok":
            h.append(f"<div class='empty'>{r['path']} was {'not found' if r['status'] == 'missing' else 'not valid JSON'}.</div>")
        elif not r["items"]:
            h.append("<div class='empty'>No findings.</div>")
        else:
            h.append("<div class='tw'><table><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Details and fix</th></tr>")
            for i in r["items"][: args.max_rows]:
                det = e(i["detail"]) + (f"<br><b>Fix:</b> {e(i['fix'])}" if i["fix"] else "")
                h.append(f"<tr><td><span class='pill s-{i['sev']}'>{i['sev'].title()}</span></td><td>{e(i['title'], 160)}</td>"
                         f"<td class='w'>{e(i['where'], 160)}</td><td>{det}</td></tr>")
            h.append("</table>")
            if len(r["items"]) > args.max_rows:
                h.append(f"<div class='empty'>Showing first {args.max_rows} of {len(r['items'])}. See {r['path']} for all.</div>")
            h.append("</div>")
        h.append("</details>")

    if comps:
        h.append(f"<details><summary>SBOM components<span class='c'>{len(comps)} packages</span></summary>"
                 "<div class='tw'><table><tr><th>Name</th><th>Version</th><th>Type</th></tr>")
        for c in sorted(comps, key=lambda x: x.get("name", ""))[: args.max_rows]:
            h.append(f"<tr><td>{e(c.get('name', ''), 80)}</td><td>{e(c.get('version', ''), 40)}</td><td>{e(c.get('type', ''), 30)}</td></tr>")
        h.append("</table></div></details>")

    h.append("<div class='foot'>Generated from Gitleaks, Bandit, Semgrep, pip-audit, Trivy, Syft and ZAP output. "
             "pip-audit does not report severity, so its findings are counted as High.</div></div></body></html>")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("".join(h))
    print(f"Wrote {args.out}: {allc} findings, {blocking} blocking -> {vclass.upper()}")
    return 1 if (blocking and args.enforce) else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=".")
    ap.add_argument("--out", default="security-report.html")
    ap.add_argument("--build", default="local")
    ap.add_argument("--commit", default="unknown")
    ap.add_argument("--fail-on", default="HIGH", choices=SEV[:4], type=str.upper)
    ap.add_argument("--max-rows", type=int, default=200)
    ap.add_argument("--enforce", action="store_true", help="exit 1 when the gate fails")
    sys.exit(build(ap.parse_args()))
