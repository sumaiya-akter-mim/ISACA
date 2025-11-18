import json
from typing import List

from .correlate import CorrelatedRisk
from .dast import DASTFinding
from .sast import SASTFinding
from .dump_audit import DumpFinding


def to_json(risk: CorrelatedRisk) -> str:
    def asdict(obj):
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return obj

    return json.dumps(
        {
            "severity": risk.severity,
            "score": risk.score,
            "reason": risk.reason,
            "dast": [asdict(f) for f in risk.dast],
            "sast": [asdict(f) for f in risk.sast],
            "dump": [asdict(f) for f in risk.dump],
        },
        indent=2,
    )


def to_markdown(risk: CorrelatedRisk) -> str:
    lines: List[str] = []
    lines.append(f"# Unified Security Report")
    lines.append("")
    lines.append(f"- Severity: {risk.severity}")
    lines.append(f"- Risk Score: {risk.score}")
    lines.append("")
    lines.append(f"## Summary")
    lines.append(risk.reason)
    lines.append("")
    lines.append("## DAST Findings")
    for f in risk.dast:
        lines.append(f"- [{f.technique}] {f.url} param={f.param} code={f.response_code} time={f.response_time_ms}ms | {f.evidence}")
    lines.append("")
    lines.append("## SAST Findings")
    for s in risk.sast:
        lines.append(f"- {s.severity} {s.file}:{s.line} | {s.issue} | {s.code_snippet}")
    lines.append("")
    lines.append("## Dump Audit Findings")
    for d in risk.dump:
        lines.append(f"- {d.severity} line {d.line_no} | {d.format} | {d.hash_sample}")
    lines.append("")
    lines.append("## Recommended Fixes")
    lines.append("- Use parameterized queries (prepared statements) for all DB interactions.")
    lines.append("- Store passwords using modern KDFs (Argon2id, bcrypt, or PBKDF2).")
    lines.append("- Rotate and reset compromised credentials; enable 2FA for sensitive accounts.")
    lines.append("- Implement WAF rules and input validation for high-risk parameters.")

    return "\n".join(lines)


def to_html(risk: CorrelatedRisk) -> str:
    severity_colors = {
        "CRITICAL": "#b00020",
        "HIGH": "#d32f2f",
        "MEDIUM": "#f57c00",
        "LOW": "#388e3c",
        "INFO": "#1976d2",
    }

    sev_color = severity_colors.get(risk.severity, "#444")

    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    html = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "  <title>Unified Security Report</title>",
        "  <style>",
        "    :root { --bg:#0f172a; --card:#111827; --text:#e5e7eb; --muted:#9ca3af; --accent:#06b6d4; }",
        "    body { margin:0; font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:var(--bg); color:var(--text); }",
        "    .container { max-width: 1000px; margin: 32px auto; padding: 0 16px; }",
        "    .header { display:flex; align-items:center; justify-content:space-between; margin-bottom:24px; }",
        "    .title { font-size: 28px; font-weight: 700; letter-spacing: 0.2px; }",
        "    .badge { padding: 6px 10px; border-radius: 999px; font-weight: 600; color:#fff; }",
        "    .meta { display:flex; gap:16px; align-items:center; color:var(--muted); margin-top:8px; }",
        "    .grid { display:grid; grid-template-columns: 1fr; gap:16px; }",
        "    @media (min-width: 920px) { .grid { grid-template-columns: 1fr 1fr; } }",
        "    .card { background:var(--card); border:1px solid #1f2937; border-radius:12px; overflow:hidden; }",
        "    .card h2 { margin:0; padding:14px 16px; border-bottom:1px solid #1f2937; font-size:16px; letter-spacing:0.2px; background:#0b1220; }",
        "    .section { padding: 10px 16px 16px; }",
        "    table { width:100%; border-collapse: collapse; }",
        "    th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #1f2937; vertical-align: top; font-size: 14px; }",
        "    th { color: var(--muted); font-weight:600; }",
        "    .code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background:#0b1220; padding:3px 6px; border-radius:6px; }",
        "    .summary { margin-top:16px; line-height:1.6; }",
        "    .fixes li { margin:6px 0; }",
        f"    .badge.sev {{ background:{sev_color}; }}",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class=\"container\">",
        "    <div class=\"header\">",
        "      <div>",
        "        <div class=\"title\">Unified Security Report</div>",
        f"        <div class=\"meta\"><span>Severity: <span class=\"badge sev\">{risk.severity}</span></span><span>Risk Score: <span class=\"code\">{risk.score}</span></span></div>",
        "      </div>",
        "    </div>",
        f"    <div class=\"summary\">{esc(risk.reason)}</div>",
        "    <div class=\"grid\" style=\"margin-top:16px;\">",
        "      <div class=\"card\">",
        "        <h2>DAST Findings</h2>",
        "        <div class=\"section\">",
        "          <table>",
        "            <thead><tr><th>Technique</th><th>URL</th><th>Param</th><th>Code</th><th>Time (ms)</th><th>Evidence</th></tr></thead>",
        "            <tbody>",
    ]

    for f in risk.dast:
        html.append(
            f"<tr><td>{esc(f.technique)}</td><td class=\"code\">{esc(f.url)}</td><td>{esc(f.param)}</td><td>{f.response_code}</td><td>{f.response_time_ms}</td><td>{esc(f.evidence)}</td></tr>"
        )

    html += [
        "            </tbody>",
        "          </table>",
        "        </div>",
        "      </div>",

        "      <div class=\"card\">",
        "        <h2>SAST Findings</h2>",
        "        <div class=\"section\">",
        "          <table>",
        "            <thead><tr><th>Severity</th><th>File:Line</th><th>Issue</th><th>Code</th></tr></thead>",
        "            <tbody>",
    ]

    for s in risk.sast:
        fileline = f"{s.file}:{s.line}"
        html.append(
            f"<tr><td>{esc(s.severity)}</td><td class=\"code\">{esc(fileline)}</td><td>{esc(s.issue)}</td><td class=\"code\">{esc(s.code_snippet)}</td></tr>"
        )

    html += [
        "            </tbody>",
        "          </table>",
        "        </div>",
        "      </div>",

        "      <div class=\"card\">",
        "        <h2>Dump Audit Findings</h2>",
        "        <div class=\"section\">",
        "          <table>",
        "            <thead><tr><th>Severity</th><th>Line</th><th>Format</th><th>Sample</th></tr></thead>",
        "            <tbody>",
    ]

    for d in risk.dump:
        html.append(
            f"<tr><td>{esc(d.severity)}</td><td>{d.line_no}</td><td>{esc(d.format)}</td><td class=\"code\">{esc(d.hash_sample)}</td></tr>"
        )

    html += [
        "            </tbody>",
        "          </table>",
        "        </div>",
        "      </div>",
        "    </div>",

        "    <div class=\"card\" style=\"margin-top:16px;\">",
        "      <h2>Recommended Fixes</h2>",
        "      <div class=\"section\">",
        "        <ul class=\"fixes\">",
        "          <li>Use parameterized queries (prepared statements) for all DB interactions.</li>",
        "          <li>Store passwords using modern KDFs (Argon2id, bcrypt, or PBKDF2).</li>",
        "          <li>Rotate and reset compromised credentials; enable 2FA for sensitive accounts.</li>",
        "          <li>Implement WAF rules and input validation for high-risk parameters.</li>",
        "        </ul>",
        "      </div>",
        "    </div>",

        "  </div>",
        "</body>",
        "</html>",
    ]

    return "".join(html)