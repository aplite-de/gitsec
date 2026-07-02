import json
from pathlib import Path
from typing import List, Optional

from ..models.finding import DependencyFinding, Finding, SecretFinding


class HtmlReportWriter:

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self._security: List[Finding] = []
        self._dependencies: List[DependencyFinding] = []
        self._deprecated: List[dict] = []
        self._unpinned: List[dict] = []
        self._secrets: List[SecretFinding] = []

    def add_security_findings(self, findings: List[Finding]) -> None:
        self._security = [f for f in findings if not f.is_error]

    def add_dependency_findings(
        self,
        vulnerabilities: List[DependencyFinding],
        deprecated: Optional[List[dict]] = None,
        unpinned: Optional[List[dict]] = None,
    ) -> None:
        self._dependencies = vulnerabilities or []
        self._deprecated = deprecated or []
        self._unpinned = unpinned or []

    def add_secret_findings(self, findings: List[SecretFinding]) -> None:
        self._secrets = findings

    def save(self) -> None:
        payload = self._build_payload()
        html = _render_html(payload)
        self.output_path.write_text(html, encoding="utf-8")

    def _build_payload(self) -> dict:
        findings = []

        for f in self._security:
            findings.append({
                "type": "check",
                "check_id": f.check_id,
                "title": f.title or f.check_id,
                "severity": f.severity or "Info",
                "category": f.category or "",
                "resource": f.resource,
                "evidence": f.evidence,
                "description": f.description or "",
                "risk": f.risk or "",
                "remediation": f.remediation or "",
                "reference_url": f.reference_url or "",
            })

        for f in self._dependencies:
            findings.append({
                "type": "dependency",
                "title": f.title,
                "severity": f.severity.capitalize() if f.severity else "Info",
                "category": "Dependency Vulnerability",
                "resource": f.repository,
                "evidence": f"{f.package}@{f.version} in {f.file_path}",
                "description": f"Advisory: {f.advisory_id}",
                "risk": f"CVSS score: {f.cvss_score}",
                "remediation": f"Update {f.package} to a patched version.",
                "reference_url": f.url,
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "cvss_score": f.cvss_score,
            })

        for f in self._secrets:
            findings.append({
                "type": "secret",
                "title": f"Exposed {f.secret_type}",
                "severity": "Critical",
                "category": "Secrets",
                "resource": f.repository,
                "evidence": f"{f.file_path}" + (f":{f.line_number}" if f.line_number else ""),
                "description": f"A {f.secret_type} was detected in the repository.",
                "risk": "Exposed credentials can be used to access systems immediately.",
                "remediation": "Rotate this credential immediately. Remove from repo history.",
                "reference_url": "",
                "secret_type": f.secret_type,
                "file_path": f.file_path,
                "line_number": f.line_number,
            })

        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda x: order.get(x.get("severity", "Info"), 4))

        counts = {}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        type_counts = {}
        for f in findings:
            t = f.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": counts,
                "by_type": type_counts,
            },
        }


def _render_html(payload: dict) -> str:
    data_json = json.dumps(payload, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@500;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<title>gitsec — Security Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #04110F;
    --bg-glow: rgba(24,226,153,.08);
    --surface: #071816;
    --surface-soft: #0B201C;
    --surface-raised: #091A17;
    --surface-2: #061411;
    --border: rgba(100, 161, 137, .22);
    --border-strong: rgba(128, 198, 170, .42);
    --text: #EAF5F0;
    --muted: #91A79E;
    --muted-2: #6F8B80;
    --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --sans: 'Manrope', Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --header: #04110F;
    --header-2: #071916;
    --accent: #67E3AF;
    --accent-muted: #44C18E;
    --accent-soft: rgba(103,227,175,.12);
    --crit: #FF6B93;
    --crit-t: #FF97B2;
    --crit-bg: rgba(255,107,147,.10);
    --high: #F3C35D;
    --high-t: #F6D78B;
    --high-bg: rgba(243,195,93,.12);
    --med: #67E3AF;
    --med-t: #89EDC0;
    --med-bg: rgba(103,227,175,.12);
    --low: #4CCB97;
    --low-t: #79DBB2;
    --low-bg: rgba(76,203,151,.11);
    --info: #7D9189;
    --info-t: #A7BAB2;
    --info-bg: rgba(125,145,137,.12);
    --unknown: #8A909A;
    --unknown-t: #C1C7D0;
    --unknown-bg: rgba(138,144,154,.13);
    --shadow: 0 14px 40px rgba(0,0,0,.22);
    --shadow-soft: 0 1px 0 rgba(255,255,255,.02), 0 6px 18px rgba(0,0,0,.18);
  }}

  html, body {{
    min-height: 100%;
    background:
      radial-gradient(circle at 0% 0%, rgba(24,226,153,.06), transparent 28%),
      radial-gradient(circle at 100% 0%, rgba(103,227,175,.04), transparent 24%),
      var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
  }}
  body {{ display: flex; flex-direction: column; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  .header {{
    background: linear-gradient(180deg, rgba(4,17,15,.98), rgba(7,25,22,.96));
    border-bottom: 1px solid var(--border);
    padding: 20px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
    box-shadow: 0 14px 32px rgba(0,0,0,.18);
  }}
  .logo {{ display: flex; align-items: center; gap: 14px; }}
  .logo-icon {{
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: linear-gradient(180deg, rgba(103,227,175,.08), rgba(103,227,175,.04));
    border: 1px solid rgba(103,227,175,.24);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
  }}
  .logo-icon svg {{ display: block; width: 22px; height: 22px; }}
  .logo-name {{
    font-size: 20px;
    line-height: 1.05;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: -0.03em;
  }}
  .logo-sub {{
    margin-top: 5px;
    font-size: 11px;
    color: rgba(193, 220, 209, .84);
    font-family: var(--mono);
    letter-spacing: .02em;
  }}
  .meta {{
    font-family: var(--mono);
    font-size: 11px;
    color: #CBE0D7;
    text-align: right;
    background: rgba(103,227,175,.06);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 8px 12px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.02);
  }}

  .main {{
    flex: 1;
    display: flex;
    min-height: 0;
    overflow: hidden;
  }}
  .list-pane {{
    flex: 1;
    overflow-y: auto;
    padding: 28px 32px 34px;
    min-width: 0;
  }}
  .detail-pane {{
    width: 440px;
    flex-shrink: 0;
    overflow-y: auto;
    background: rgba(7, 24, 22, .96);
    border-left: 1px solid var(--border);
    padding: 28px;
    display: none;
    box-shadow: -12px 0 30px rgba(0,0,0,.18);
  }}
  .detail-pane.open {{ display: block; }}

  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(126px, 1fr));
    gap: 12px;
    margin-bottom: 22px;
  }}
  .card {{
    position: relative;
    background: linear-gradient(180deg, rgba(9,26,23,.95), rgba(6,20,17,.95));
    border: 1.5px solid rgba(255,255,255,.72);
    border-radius: 14px;
    padding: 15px 16px 14px;
    min-width: 0;
    box-shadow: 0 0 0 1px rgba(255,255,255,.06), var(--shadow-soft);
    overflow: hidden;
  }}
  .card::before {{
    content: '';
    position: absolute;
    inset: 0;
    border-radius: inherit;
    pointer-events: none;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.16);
  }}
  .card-num {{
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 800;
    line-height: 1;
    letter-spacing: -0.04em;
    color: #FFFFFF;
  }}
  .card-label {{
    font-size: 10px;
    color: var(--muted);
    margin-top: 7px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .08em;
  }}

  .filters {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 12px;
    background: linear-gradient(180deg, rgba(9,26,23,.94), rgba(6,20,17,.96));
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 10px;
    box-shadow: var(--shadow-soft);
  }}
  .filters input {{
    background: rgba(103,227,175,.05);
    border: 1px solid rgba(100,161,137,.16);
    color: var(--text);
    border-radius: 10px;
    padding: 10px 12px;
    font-size: 12px;
    font-family: var(--mono);
    outline: none;
    width: 230px;
    min-height: 38px;
  }}
  .filters input::placeholder {{ color: var(--muted-2); }}
  .filters input:focus {{
    border-color: rgba(103,227,175,.40);
    box-shadow: 0 0 0 3px rgba(103,227,175,.12);
  }}
  .filter-group {{
    display: flex;
    align-items: center;
    gap: 6px;
    background: rgba(103,227,175,.035);
    border: 1px solid rgba(255,255,255,.28);
    border-radius: 12px;
    padding: 8px 12px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
  }}
  .filter-label {{
    font-size: 10px;
    color: #FFFFFF;
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .12em;
    font-family: var(--mono);
    margin-right: 8px;
    white-space: nowrap;
    opacity: .98;
    text-decoration: underline;
    text-decoration-thickness: 1px;
    text-underline-offset: 4px;
    text-decoration-color: rgba(255,255,255,.78);
    text-shadow: 0 0 10px rgba(255,255,255,.16);
  }}
  .filter-btn {{
    background: transparent;
    border: 1px solid transparent;
    color: #B7CBC3;
    border-radius: 999px;
    padding: 7px 10px;
    cursor: pointer;
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .05em;
    font-family: var(--mono);
    transition: background .14s, border-color .14s, color .14s, box-shadow .14s;
  }}
  .filter-btn:hover {{
    border-color: rgba(103,227,175,.18);
    color: var(--text);
    background: rgba(103,227,175,.06);
  }}
  .filter-btn.active,
  .filter-btn.active-medi,
  .filter-btn.active-low {{
    background: rgba(103,227,175,.14);
    border-color: rgba(103,227,175,.32);
    color: var(--med-t);
  }}
  .filter-btn.active-crit {{ background: var(--crit-bg); border-color: rgba(255,107,147,.34); color: var(--crit-t); }}
  .filter-btn.active-high {{ background: var(--high-bg); border-color: rgba(243,195,93,.30); color: var(--high-t); }}
  .filter-btn.active-unkn {{ background: var(--unknown-bg); border-color: rgba(138,144,154,.30); color: var(--unknown-t); }}

  .result-count {{
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
    margin: 14px 2px 10px;
  }}

  .table {{
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
    background: linear-gradient(180deg, rgba(9,26,23,.96), rgba(6,20,17,.98));
    box-shadow: var(--shadow);
  }}
  .table-head {{
    display: grid;
    grid-template-columns: 108px 116px minmax(260px, 1fr) 180px;
    padding: 11px 18px;
    background: rgba(103,227,175,.04);
    border-bottom: 1px solid var(--border);
    gap: 12px;
  }}
  .table-head span:nth-child(1),
  .row > div:nth-child(1) {{ text-align: left; }}
  .table-head span {{
    font-size: 10px;
    color: var(--muted-2);
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .1em;
    font-family: var(--mono);
  }}
  .row {{
    display: grid;
    grid-template-columns: 108px 116px minmax(260px, 1fr) 180px;
    padding: 14px 18px;
    border-bottom: 1px solid rgba(100,161,137,.12);
    gap: 12px;
    cursor: pointer;
    align-items: center;
    border-left: 3px solid transparent;
    transition: background .12s, border-color .12s;
    background: transparent;
  }}
  .row:last-child {{ border-bottom: 0; }}
  .row:hover {{ background: rgba(103,227,175,.04); }}
  .row.selected {{
    border-left-color: var(--accent);
    background: rgba(103,227,175,.06);
  }}
  .row-title {{
    font-size: 13px;
    font-weight: 700;
    color: var(--text);
    line-height: 1.35;
  }}
  .row-cat {{
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
  }}
  .row-res {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }}
  .empty {{
    padding: 44px;
    text-align: center;
    color: var(--muted);
    font-size: 13px;
  }}

  .sev-badge, .type-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .05em;
    font-family: var(--mono);
    white-space: nowrap;
    background: rgba(103,227,175,.05);
    border: 1px solid rgba(100,161,137,.20);
    min-width: 78px;
  }}
  .type-badge {{ min-width: 86px; }}
  .dot {{ width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }}
  .sev-Critical {{ background: var(--crit-bg); border-color: rgba(255,107,147,.32); color: var(--crit-t); }}
  .sev-High {{ background: var(--high-bg); border-color: rgba(243,195,93,.28); color: var(--high-t); }}
  .sev-Medium {{ background: var(--med-bg); border-color: rgba(103,227,175,.30); color: var(--med-t); }}
  .sev-Low {{ background: var(--low-bg); border-color: rgba(76,203,151,.26); color: var(--low-t); }}
  .sev-Info {{ background: var(--info-bg); border-color: rgba(125,145,137,.24); color: var(--info-t); }}
  .sev-Unknown {{ background: var(--unknown-bg); border-color: rgba(138,144,154,.24); color: var(--unknown-t); }}

  .type-check {{ background: rgba(103,227,175,.06); border-color: rgba(103,227,175,.18); color: #8EEDC2; }}
  .type-dependency {{ background: rgba(103,227,175,.07); border-color: rgba(103,227,175,.24); color: var(--accent); }}
  .type-secret {{ background: rgba(255,107,147,.10); border-color: rgba(255,107,147,.22); color: var(--crit-t); }}

  .close-btn {{
    background: rgba(103,227,175,.05);
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 999px;
    padding: 8px 13px;
    cursor: pointer;
    font-size: 11px;
    font-family: var(--mono);
    font-weight: 700;
    margin-bottom: 22px;
  }}
  .close-btn:hover {{
    border-color: rgba(103,227,175,.28);
    color: var(--accent);
    background: rgba(103,227,175,.09);
  }}
  .detail-badges {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
  .detail-title {{
    font-size: 18px;
    font-weight: 800;
    color: var(--text);
    margin-bottom: 7px;
    line-height: 1.35;
    letter-spacing: -0.02em;
  }}
  .detail-id {{
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 22px;
  }}
  .section {{ margin-bottom: 18px; }}
  .section-label {{
    font-size: 10px;
    color: var(--muted-2);
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .1em;
    margin-bottom: 8px;
    font-family: var(--mono);
  }}
  .section p {{ font-size: 13px; color: #B9CCC5; line-height: 1.65; }}

  .code-block,
  .risk-block,
  .fix-block,
  .warn-block {{
    border-radius: 12px;
    padding: 12px 13px;
    font-size: 12px;
    line-height: 1.55;
  }}
  .code-block {{
    background: rgba(103,227,175,.04);
    border: 1px solid rgba(100,161,137,.16);
    font-family: var(--mono);
    word-break: break-all;
    color: var(--text);
  }}
  .risk-block {{
    background: var(--high-bg);
    border: 1px solid rgba(243,195,93,.24);
    color: var(--high-t);
  }}
  .fix-block {{
    background: var(--med-bg);
    border: 1px solid rgba(103,227,175,.22);
    color: var(--med-t);
  }}
  .warn-block {{
    background: var(--crit-bg);
    border: 1px solid rgba(255,107,147,.24);
    color: var(--crit-t);
    font-size: 12px;
  }}


  /* Detail panel text normalization */
  .detail-pane,
  .detail-pane * {{
    color: #FFFFFF !important;
  }}
  .detail-pane .section-label,
  .detail-pane .detail-id,
  .detail-pane .section p,
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block,
  .detail-pane a {{
    color: #FFFFFF !important;
  }}
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    border-color: rgba(255,255,255,.22);
  }}
  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    color: #FFFFFF !important;
    border-color: rgba(255,255,255,.32);
  }}



  /* Sidebar minimal uniform refinement */
  .detail-pane {{
    background: linear-gradient(180deg, #04110F 0%, #061915 100%) !important;
    border-left: 1px solid rgba(255,255,255,.72) !important;
    padding: 30px !important;
  }}

  .detail-pane,
  .detail-pane * {{
    font-family: var(--sans) !important;
    color: #FFFFFF !important;
  }}

  .detail-pane .close-btn {{
    background: transparent !important;
    border: 1px solid rgba(255,255,255,.75) !important;
    color: #FFFFFF !important;
    border-radius: 999px !important;
    padding: 8px 14px !important;
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: 0 !important;
  }}

  .detail-pane .detail-badges {{
    gap: 8px !important;
    margin-bottom: 18px !important;
  }}

  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    background: transparent !important;
    border: 1px solid rgba(255,255,255,.78) !important;
    color: #FFFFFF !important;
    font-family: var(--sans) !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    letter-spacing: .02em !important;
    text-transform: uppercase !important;
    padding: 6px 11px !important;
    min-width: auto !important;
  }}

  .detail-pane .sev-Critical .dot {{
    background: #FF3B4F !important;
  }}

  .detail-pane .detail-title {{
    color: #FFFFFF !important;
    font-family: var(--sans) !important;
    font-size: 20px !important;
    line-height: 1.35 !important;
    font-weight: 800 !important;
    letter-spacing: -0.02em !important;
    margin-bottom: 6px !important;
  }}

  .detail-pane .detail-id {{
    color: rgba(255,255,255,.84) !important;
    font-family: var(--sans) !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    margin-bottom: 24px !important;
  }}

  .detail-pane .section {{
    margin-bottom: 18px !important;
  }}

  .detail-pane .section-label {{
    color: rgba(255,255,255,.86) !important;
    font-family: var(--sans) !important;
    font-size: 11px !important;
    font-weight: 800 !important;
    letter-spacing: .08em !important;
    text-transform: uppercase !important;
    margin-bottom: 8px !important;
  }}

  .detail-pane .section p {{
    color: #FFFFFF !important;
    font-family: var(--sans) !important;
    font-size: 14px !important;
    line-height: 1.6 !important;
    font-weight: 500 !important;
  }}

  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    background: rgba(255,255,255,.045) !important;
    border: 1px solid rgba(255,255,255,.72) !important;
    border-radius: 10px !important;
    color: #FFFFFF !important;
    font-family: var(--sans) !important;
    font-size: 14px !important;
    line-height: 1.55 !important;
    font-weight: 600 !important;
    padding: 13px 14px !important;
    box-shadow: none !important;
    word-break: break-word !important;
  }}

  .detail-pane .code-block + *,
  .detail-pane .risk-block + *,
  .detail-pane .fix-block + *,
  .detail-pane .warn-block + * {{
    margin-top: 0 !important;
  }}

  @media (max-width: 980px) {{
    .main {{ display: block; overflow: auto; }}
    .list-pane {{ padding: 22px 18px; }}
    .detail-pane {{ width: auto; border-left: 0; border-top: 1px solid var(--border); box-shadow: none; }}
    .table-head, .row {{ grid-template-columns: 96px 104px minmax(180px, 1fr); }}
    .table-head span:nth-child(4), .row > div:nth-child(4) {{ display: none; }}
  }}
  @media (max-width: 680px) {{
    .header {{ padding: 18px; }}
    .meta {{ width: 100%; text-align: left; }}
    .filters input {{ width: 100%; }}
    .filter-group {{ width: 100%; border: 1px solid rgba(255,255,255,.24); padding: 10px 12px; flex-wrap: wrap; }}
    .table-head {{ display: none; }}
    .row {{ grid-template-columns: 1fr; gap: 8px; }}
  }}


  /* Header and pill refinement */
  .header {{
    padding: 28px 40px !important;
    min-height: 96px !important;
  }}
  .logo {{
    gap: 16px !important;
  }}
  .logo-icon {{
    width: 54px !important;
    height: 54px !important;
    border-radius: 14px !important;
  }}
  .logo-icon svg {{
    width: 28px !important;
    height: 28px !important;
  }}
  .logo-name {{
    font-size: 27px !important;
    line-height: 1 !important;
    letter-spacing: -0.04em !important;
  }}
  .logo-sub {{
    color: #9fd !important;
    font-family: var(--sans) !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    letter-spacing: .01em !important;
    margin-top: 7px !important;
  }}
  .meta {{
    font-size: 12px !important;
    padding: 9px 14px !important;
  }}

  .sev-badge,
  .type-badge {{
    font-family: var(--sans) !important;
    font-size: 12px !important;
    font-weight: 800 !important;
    letter-spacing: .03em !important;
    padding: 7px 12px !important;
    border-width: 1.25px !important;
  }}
  .type-badge {{
    min-width: 96px !important;
  }}

  .sev-Critical {{
    background: rgba(255, 59, 79, .16) !important;
    border-color: rgba(255, 92, 112, .76) !important;
    color: #FFFFFF !important;
  }}
  .sev-High {{
    background: rgba(246, 183, 62, .16) !important;
    border-color: rgba(246, 211, 124, .72) !important;
    color: #FFE7A6 !important;
  }}
  .sev-Medium {{
    background: rgba(103, 227, 175, .15) !important;
    border-color: rgba(103, 227, 175, .70) !important;
    color: #D7FFEC !important;
  }}
  .sev-Low {{
    background: rgba(128, 214, 165, .13) !important;
    border-color: rgba(154, 230, 190, .58) !important;
    color: #D8FBE9 !important;
  }}
  .sev-Unknown,
  .sev-Info {{
    background: rgba(255, 255, 255, .08) !important;
    border-color: rgba(255, 255, 255, .46) !important;
    color: #FFFFFF !important;
  }}

  .type-check {{
    background: rgba(103, 227, 175, .12) !important;
    border-color: rgba(103, 227, 175, .56) !important;
    color: #E7FFF4 !important;
  }}
  .type-dependency {{
    background: rgba(90, 180, 255, .13) !important;
    border-color: rgba(130, 204, 255, .58) !important;
    color: #E6F5FF !important;
  }}
  .type-secret {{
    background: rgba(255, 92, 112, .14) !important;
    border-color: rgba(255, 128, 145, .62) !important;
    color: #FFFFFF !important;
  }}

  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    font-size: 12px !important;
    padding: 7px 12px !important;
    border-width: 1.25px !important;
  }}
  .detail-pane .type-badge.type-secret {{
    background: rgba(255, 92, 112, .14) !important;
    border-color: rgba(255, 128, 145, .62) !important;
  }}
  .detail-pane .sev-Critical {{
    background: rgba(255, 59, 79, .16) !important;
    border-color: rgba(255, 92, 112, .76) !important;
  }}
  .detail-pane .sev-Critical .dot {{
    background: #FF3B4F !important;
  }}



  /* Refined theme: dimmer pills, centered cards, readable sidebar */
  :root {{
    --theme-border: rgba(103, 227, 175, .36);
    --theme-border-strong: rgba(103, 227, 175, .52);
    --theme-panel: rgba(103, 227, 175, .045);
    --theme-panel-hover: rgba(103, 227, 175, .075);
  }}

  .card {{
    display: flex !important;
    flex-direction: column !important;
    align-items: center !important;
    justify-content: center !important;
    text-align: center !important;
    min-height: 86px !important;
    border: 1.5px solid var(--theme-border-strong) !important;
    background: linear-gradient(180deg, rgba(9,26,23,.96), rgba(6,20,17,.98)) !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.04), 0 8px 22px rgba(0,0,0,.18) !important;
  }}
  .card::before {{ box-shadow: none !important; }}
  .card-num {{
    font-size: 32px !important;
    line-height: 1 !important;
    text-align: center !important;
  }}
  .card-label {{
    margin-top: 9px !important;
    font-size: 12px !important;
    color: rgba(234,245,240,.88) !important;
    text-align: center !important;
    letter-spacing: .08em !important;
  }}

  .sev-badge,
  .type-badge {{
    color: #EAF5F0 !important;
    font-size: 12px !important;
    font-weight: 800 !important;
    padding: 7px 13px !important;
    border-width: 1.25px !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.035) !important;
  }}
  .sev-Critical {{
    background: rgba(215, 62, 84, .14) !important;
    border-color: rgba(215, 62, 84, .48) !important;
    color: #FFD8DF !important;
  }}
  .sev-High {{
    background: rgba(205, 143, 45, .15) !important;
    border-color: rgba(205, 143, 45, .48) !important;
    color: #FFE6B4 !important;
  }}
  .sev-Medium {{
    background: rgba(88, 177, 132, .15) !important;
    border-color: rgba(88, 177, 132, .48) !important;
    color: #D9F7E8 !important;
  }}
  .sev-Low {{
    background: rgba(80, 139, 116, .16) !important;
    border-color: rgba(104, 166, 141, .42) !important;
    color: #D4ECE2 !important;
  }}
  .sev-Unknown,
  .sev-Info {{
    background: rgba(145, 167, 158, .13) !important;
    border-color: rgba(145, 167, 158, .36) !important;
    color: #DEEAE5 !important;
  }}
  .type-check {{
    background: rgba(88, 177, 132, .13) !important;
    border-color: rgba(88, 177, 132, .42) !important;
    color: #DEF8EB !important;
  }}
  .type-dependency {{
    background: rgba(82, 142, 170, .14) !important;
    border-color: rgba(105, 165, 193, .42) !important;
    color: #DDEFF6 !important;
  }}
  .type-secret {{
    background: rgba(215, 62, 84, .13) !important;
    border-color: rgba(215, 62, 84, .42) !important;
    color: #FFE1E6 !important;
  }}

  .detail-pane {{
    background: linear-gradient(180deg, #04110F 0%, #061915 100%) !important;
    border-left: 1px solid var(--theme-border-strong) !important;
  }}
  .detail-pane,
  .detail-pane * {{
    font-family: var(--sans) !important;
  }}
  .detail-pane .detail-title {{
    font-size: 22px !important;
    line-height: 1.3 !important;
    margin-bottom: 8px !important;
  }}
  .detail-pane .detail-id {{
    font-size: 14px !important;
    color: rgba(234,245,240,.86) !important;
  }}
  .detail-pane .section-label {{
    font-family: var(--sans) !important;
    font-size: 12px !important;
    font-weight: 900 !important;
    letter-spacing: .10em !important;
    color: #FFFFFF !important;
    margin-bottom: 10px !important;
  }}
  .detail-pane .section p {{
    font-size: 15px !important;
    line-height: 1.65 !important;
    color: #FFFFFF !important;
  }}
  .detail-pane .close-btn,
  .detail-pane .sev-badge,
  .detail-pane .type-badge,
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    border-color: var(--theme-border-strong) !important;
    background: var(--theme-panel) !important;
    color: #FFFFFF !important;
  }}
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    min-height: 48px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    text-align: center !important;
    border-radius: 12px !important;
    padding: 14px 16px !important;
    font-size: 16px !important;
    line-height: 1.45 !important;
    font-weight: 700 !important;
    word-break: break-word !important;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.035) !important;
  }}
  .detail-pane .close-btn:hover,
  .detail-pane .code-block:hover,
  .detail-pane .risk-block:hover,
  .detail-pane .fix-block:hover,
  .detail-pane .warn-block:hover {{
    background: var(--theme-panel-hover) !important;
  }}
  .detail-pane .sev-Critical {{
    background: rgba(215, 62, 84, .14) !important;
    border-color: rgba(215, 62, 84, .48) !important;
    color: #FFD8DF !important;
  }}
  .detail-pane .sev-High {{
    background: rgba(205, 143, 45, .15) !important;
    border-color: rgba(205, 143, 45, .48) !important;
    color: #FFE6B4 !important;
  }}
  .detail-pane .sev-Medium {{
    background: rgba(88, 177, 132, .15) !important;
    border-color: rgba(88, 177, 132, .48) !important;
    color: #D9F7E8 !important;
  }}
  .detail-pane .sev-Low {{
    background: rgba(80, 139, 116, .16) !important;
    border-color: rgba(104, 166, 141, .42) !important;
    color: #D4ECE2 !important;
  }}
  .detail-pane .type-check {{
    background: rgba(88, 177, 132, .13) !important;
    border-color: rgba(88, 177, 132, .42) !important;
    color: #DEF8EB !important;
  }}
  .detail-pane .type-dependency {{
    background: rgba(82, 142, 170, .14) !important;
    border-color: rgba(105, 165, 193, .42) !important;
    color: #DDEFF6 !important;
  }}
  .detail-pane .type-secret {{
    background: rgba(215, 62, 84, .13) !important;
    border-color: rgba(215, 62, 84, .42) !important;
    color: #FFE1E6 !important;
  }}
  .detail-pane .sev-Critical .dot {{
    background: #E5485E !important;
  }}



  /* Final readability refinement */
  :root {{
    --sans: Arial, Helvetica, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }}

  body,
  button,
  input {{
    font-family: var(--sans) !important;
  }}

  .table-head span {{
    font-family: var(--sans) !important;
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: .08em !important;
    color: #9FC7B7 !important;
  }}

  .row {{
    min-height: 72px !important;
    padding: 18px 20px !important;
  }}

  .row-title {{
    font-family: var(--sans) !important;
    font-size: 16px !important;
    font-weight: 600 !important;
    line-height: 1.35 !important;
    color: #F4FFFA !important;
  }}

  .row-cat,
  .row-res,
  .result-count {{
    font-family: var(--sans) !important;
    font-size: 13px !important;
    font-weight: 400 !important;
    color: #9EC7B6 !important;
  }}

  .sev-badge,
  .type-badge {{
    width: 116px !important;
    min-width: 116px !important;
    height: 34px !important;
    padding: 0 12px !important;
    justify-content: center !important;
    text-align: center !important;
    font-family: var(--sans) !important;
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .02em !important;
    border-radius: 999px !important;
    line-height: 1 !important;
  }}

  .type-badge {{
    width: 118px !important;
    min-width: 118px !important;
  }}

  .sev-Critical {{
    background: rgba(185, 28, 28, .18) !important;
    border-color: rgba(248, 113, 113, .55) !important;
    color: #FCA5A5 !important;
  }}

  .sev-High {{
    background: rgba(180, 83, 9, .18) !important;
    border-color: rgba(251, 191, 36, .55) !important;
    color: #FCD34D !important;
  }}

  .sev-Medium {{
    background: rgba(13, 148, 136, .16) !important;
    border-color: rgba(94, 234, 212, .38) !important;
    color: #99F6E4 !important;
  }}

  .sev-Low {{
    background: rgba(22, 101, 52, .16) !important;
    border-color: rgba(134, 239, 172, .36) !important;
    color: #BBF7D0 !important;
  }}

  .sev-Unknown,
  .sev-Info {{
    background: rgba(107, 114, 128, .16) !important;
    border-color: rgba(209, 213, 219, .32) !important;
    color: #D1D5DB !important;
  }}

  .type-secret {{
    background: rgba(127, 29, 29, .16) !important;
    border-color: rgba(252, 165, 165, .34) !important;
    color: #FECACA !important;
  }}

  .type-dependency {{
    background: rgba(6, 95, 70, .18) !important;
    border-color: rgba(110, 231, 183, .36) !important;
    color: #A7F3D0 !important;
  }}

  .type-check {{
    background: rgba(30, 64, 175, .15) !important;
    border-color: rgba(147, 197, 253, .34) !important;
    color: #BFDBFE !important;
  }}

  .dot {{
    width: 7px !important;
    height: 7px !important;
  }}

  .detail-pane {{
    background: #04110F !important;
    border-left: 1px solid rgba(255,255,255,.20) !important;
  }}

  .detail-pane,
  .detail-pane * {{
    font-family: var(--sans) !important;
  }}

  .detail-pane .detail-title {{
    font-size: 21px !important;
    font-weight: 600 !important;
    line-height: 1.35 !important;
    color: #FFFFFF !important;
  }}

  .detail-pane .detail-id {{
    font-size: 14px !important;
    font-weight: 400 !important;
    color: #C7DAD2 !important;
  }}

  .detail-pane .section-label {{
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .08em !important;
    color: #FFFFFF !important;
    margin-bottom: 10px !important;
  }}

  .detail-pane .section p {{
    font-size: 15px !important;
    font-weight: 400 !important;
    line-height: 1.6 !important;
    color: #E9F6F1 !important;
  }}

  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    min-height: 48px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    text-align: center !important;
    padding: 12px 16px !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255,255,255,.22) !important;
    background: rgba(255,255,255,.035) !important;
    color: #FFFFFF !important;
    font-size: 15px !important;
    font-weight: 400 !important;
    line-height: 1.45 !important;
    box-shadow: none !important;
  }}

  .detail-pane .close-btn {{
    font-size: 13px !important;
    font-weight: 600 !important;
    border: 1px solid rgba(255,255,255,.28) !important;
    background: rgba(255,255,255,.035) !important;
  }}

  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    width: 118px !important;
    min-width: 118px !important;
    height: 34px !important;
    font-size: 13px !important;
    font-weight: 700 !important;
    justify-content: center !important;
  }}

  .detail-pane .sev-Critical .dot {{
    background: #EF4444 !important;
  }}

  .filter-btn,
  .filter-label,
  .filters input {{
    font-family: var(--sans) !important;
  }}

</style>

<style id="final-theme-refinement">
  :root {{
    --sans: 'Segoe UI', Arial, Helvetica, sans-serif;
    --crit: #F05B6E;
    --crit-t: #FFB1BC;
    --crit-bg: rgba(240,91,110,.10);
    --high: #F29B52;
    --high-t: #FFD3A8;
    --high-bg: rgba(242,155,82,.10);
    --med: #E7C35A;
    --med-t: #F7E6AA;
    --med-bg: rgba(231,195,90,.10);
    --low: #6FA8FF;
    --low-t: #C8DEFF;
    --low-bg: rgba(111,168,255,.10);
  }}

  body,
  input,
  button,
  .table-head span,
  .row-title,
  .row-cat,
  .row-res,
  .sev-badge,
  .type-badge,
  .section-label,
  .section p,
  .code-block,
  .risk-block,
  .fix-block,
  .warn-block {{
    font-family: var(--sans) !important;
  }}

  .filters {{
    display: grid !important;
    grid-template-columns: minmax(250px, 320px) minmax(500px, 1.15fr) minmax(360px, .85fr);
    gap: 12px;
    align-items: stretch;
    padding: 12px;
  }}
  .filters input {{
    width: 100% !important;
    max-width: none !important;
    min-height: 48px;
    padding: 12px 16px;
    font-size: 15px !important;
    font-weight: 500;
    letter-spacing: .01em;
    border-radius: 14px;
  }}
  .filter-group {{
    width: 100%;
    min-height: 48px;
    justify-content: flex-start;
    gap: 10px;
    padding: 10px 14px;
  }}
  .filter-label {{
    font-size: 14px !important;
    font-weight: 700 !important;
    letter-spacing: .06em !important;
    margin-right: 10px !important;
  }}
  .filter-btn {{
    font-size: 13px !important;
    font-weight: 600 !important;
    padding: 9px 14px !important;
    min-width: 92px;
    text-align: center;
  }}

  .result-count {{
    font-size: 15px !important;
    font-weight: 600;
  }}

  .table-head,
  .row {{
    grid-template-columns: 124px 124px minmax(420px, 560px) 180px !important;
    justify-content: start !important;
    gap: 14px !important;
  }}
  .table-head {{
    padding: 14px 18px !important;
  }}
  .table-head span {{
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: .10em !important;
  }}
  .row {{
    padding: 18px 18px !important;
    min-height: 76px;
  }}
  .row-title {{
    font-size: 16px !important;
    font-weight: 600 !important;
    letter-spacing: -.01em;
    line-height: 1.35;
  }}
  .row-cat,
  .row-res {{
    font-size: 14px !important;
    font-weight: 400 !important;
    line-height: 1.4;
  }}

  .sev-badge,
  .type-badge {{
    min-width: 116px !important;
    justify-content: center !important;
    text-align: center !important;
    padding: 9px 14px !important;
    font-size: 13px !important;
    font-weight: 600 !important;
    border-width: 1px !important;
  }}
  .type-badge {{ min-width: 118px !important; }}

  .sev-Critical {{
    background: rgba(240,91,110,.10) !important;
    border-color: rgba(240,91,110,.52) !important;
    color: #FFB1BC !important;
  }}
  .sev-High {{
    background: rgba(242,155,82,.11) !important;
    border-color: rgba(242,155,82,.52) !important;
    color: #FFD3A8 !important;
  }}
  .sev-Medium {{
    background: rgba(231,195,90,.10) !important;
    border-color: rgba(231,195,90,.48) !important;
    color: #F7E6AA !important;
  }}
  .sev-Low {{
    background: rgba(111,168,255,.10) !important;
    border-color: rgba(111,168,255,.46) !important;
    color: #C8DEFF !important;
  }}
  .sev-Unknown {{
    background: rgba(138,144,154,.13) !important;
    border-color: rgba(138,144,154,.34) !important;
    color: #C1C7D0 !important;
  }}
  .sev-Critical .dot {{ background: #F16A78 !important; }}
  .sev-High .dot {{ background: #F2A35A !important; }}
  .sev-Medium .dot {{ background: #E5C85E !important; }}
  .sev-Low .dot {{ background: #78ADFF !important; }}
  .sev-Unknown .dot {{ background: #A9AFB8 !important; }}

  .detail-pane {{
    width: 460px;
  }}
  .detail-title {{
    font-size: 28px !important;
    font-weight: 600 !important;
    line-height: 1.25 !important;
  }}
  .detail-id {{
    font-size: 16px !important;
    font-weight: 400 !important;
    color: rgba(255,255,255,.76) !important;
  }}
  .section-label {{
    font-size: 12px !important;
    font-weight: 700 !important;
    letter-spacing: .08em !important;
    color: rgba(235,245,240,.88) !important;
  }}
  .detail-pane .section p {{
    font-size: 16px !important;
    font-weight: 400 !important;
    line-height: 1.6 !important;
    color: #F3FAF7 !important;
  }}
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    border: 1px solid rgba(146,177,167,.38) !important;
    background: rgba(255,255,255,.02) !important;
    border-radius: 14px !important;
    min-height: 48px;
    padding: 14px 16px !important;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    font-size: 18px !important;
    font-weight: 400 !important;
    line-height: 1.45 !important;
  }}
  .detail-pane .close-btn {{
    font-size: 14px !important;
    font-weight: 600 !important;
    padding: 10px 15px !important;
  }}
  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    font-size: 12px !important;
    font-weight: 600 !important;
    min-width: 114px !important;
  }}

  @media (max-width: 1200px) {{
    .filters {{
      grid-template-columns: minmax(250px, 320px) 1fr;
    }}
    .filter-group:last-child {{
      grid-column: 1 / -1;
    }}
    .table-head,
    .row {{
      grid-template-columns: 118px 118px minmax(320px, 1fr) 170px !important;
    }}
  }}

  @media (max-width: 980px) {{
    .filters {{
      grid-template-columns: 1fr;
    }}
  }}
</style>


<style id="sidebar-link-layout-fix">
  :root {{
    --detail-green-text: #8FE6C4;
    --link-hover-blue: #58A6FF;
  }}

  /* Prevent filter collisions when the sidebar is open */
  .filters {{
    display: flex !important;
    flex-wrap: wrap !important;
    align-items: stretch !important;
    gap: 12px !important;
  }}
  .filters input {{
    flex: 1 1 260px !important;
    min-width: 240px !important;
    max-width: 340px !important;
  }}
  .filter-group {{
    flex: 1 1 360px !important;
    min-width: 0 !important;
    flex-wrap: wrap !important;
    align-content: center !important;
    row-gap: 8px !important;
  }}
  .filter-group:first-of-type {{
    flex-basis: 520px !important;
  }}
  .filter-btn {{
    min-width: 78px !important;
    flex: 0 0 auto !important;
  }}

  /* Keep table columns balanced with enough room for Finding and Resource */
  .table-head,
  .row {{
    grid-template-columns: 124px 124px minmax(360px, 1fr) 190px !important;
    gap: 14px !important;
  }}
  .row-title {{
    font-size: 17px !important;
    line-height: 1.35 !important;
  }}
  .row-cat,
  .row-res {{
    font-size: 15px !important;
  }}

  /* Sidebar textbox text follows the same green tone as the category text */
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    color: var(--detail-green-text) !important;
    border-color: rgba(143,230,196,.34) !important;
    background: rgba(143,230,196,.025) !important;
    font-weight: 400 !important;
  }}
  .detail-pane .section p,
  .detail-pane .detail-id {{
    color: var(--detail-green-text) !important;
    font-weight: 400 !important;
  }}

  /* Make sidebar reference links behave like clear hyperlinks */
  .detail-pane a {{
    color: var(--detail-green-text) !important;
    text-decoration: none !important;
    word-break: break-word;
    overflow-wrap: anywhere;
    transition: color .15s ease, text-decoration-color .15s ease;
  }}
  .detail-pane a:hover {{
    color: var(--link-hover-blue) !important;
    text-decoration: underline !important;
    text-decoration-thickness: 1.5px !important;
    text-underline-offset: 3px !important;
  }}

  .detail-pane {{
    width: clamp(420px, 28vw, 500px) !important;
  }}
  .detail-pane .detail-title {{
    overflow-wrap: anywhere;
  }}

  @media (max-width: 1250px) {{
    .table-head,
    .row {{
      grid-template-columns: 118px 118px minmax(280px, 1fr) 160px !important;
    }}
    .filter-group:first-of-type,
    .filter-group {{
      flex-basis: 100% !important;
    }}
    .filters input {{
      max-width: none !important;
    }}
  }}

  @media (max-width: 980px) {{
    .detail-pane {{
      width: auto !important;
    }}
    .table-head,
    .row {{
      grid-template-columns: 112px 112px minmax(220px, 1fr) !important;
    }}
  }}
</style>


<style id="final-user-refinement">
  :root {{
    --sans: Arial, Helvetica, 'Segoe UI', sans-serif;
    --crit: #E94B4B;
    --crit-t: #FF7D7D;
    --crit-bg: rgba(233,75,75,.12);
    --high: #F08A24;
    --high-t: #FFB15F;
    --high-bg: rgba(240,138,36,.12);
    --med: #E0BE42;
    --med-t: #F3DE8A;
    --med-bg: rgba(224,190,66,.12);
    --low: #4C93F0;
    --low-t: #95C0FF;
    --low-bg: rgba(76,147,240,.12);
    --sidebar-accent: #8DD6C4;
    --sidebar-border: rgba(141,214,196,.28);
  }}

  html, body,
  input, button,
  .table-head span,
  .row-title, .row-cat, .row-res,
  .sev-badge, .type-badge,
  .section-label, .section p,
  .code-block, .risk-block, .fix-block, .warn-block,
  .detail-title, .detail-id {{
    font-family: var(--sans) !important;
  }}

  /* No double-line in top filters */
  .filters {{
    display: flex !important;
    flex-wrap: nowrap !important;
    align-items: center !important;
    gap: 12px !important;
    overflow-x: auto !important;
    overflow-y: hidden !important;
    padding: 12px !important;
    scrollbar-width: none;
  }}
  .filters::-webkit-scrollbar {{ display: none; }}
  .filters > * {{ flex: 0 0 auto; }}
  .filters input {{
    width: 300px !important;
    min-width: 300px !important;
    min-height: 52px !important;
    font-size: 16px !important;
    font-weight: 500 !important;
    padding: 14px 16px !important;
    border-radius: 16px !important;
  }}
  .filter-group {{
    flex-wrap: nowrap !important;
    gap: 10px !important;
    padding: 11px 14px !important;
    min-height: 52px !important;
    border-radius: 16px !important;
  }}
  .filter-label {{
    font-size: 15px !important;
    font-weight: 700 !important;
    letter-spacing: .04em !important;
    margin-right: 10px !important;
    text-decoration-thickness: 1px !important;
  }}
  .filter-btn {{
    min-width: 86px !important;
    padding: 9px 12px !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    text-align: center !important;
  }}

  /* Better column spacing */
  .table-head,
  .row {{
    grid-template-columns: 120px 138px minmax(300px, 1fr) 180px !important;
    gap: 18px !important;
  }}
  .table-head span {{
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .08em !important;
  }}
  .row {{
    padding: 20px 22px !important;
    min-height: 78px !important;
  }}
  .row-title {{
    font-size: 18px !important;
    font-weight: 600 !important;
    line-height: 1.3 !important;
    letter-spacing: -.01em !important;
  }}
  .row-cat {{
    font-size: 14px !important;
    font-weight: 500 !important;
    color: var(--sidebar-accent) !important;
    margin-top: 6px !important;
  }}
  .row-res {{
    font-size: 15px !important;
    font-weight: 500 !important;
    color: var(--sidebar-accent) !important;
  }}

  /* More contrasted severity colors */
  .sev-badge,
  .type-badge {{
    min-width: 118px !important;
    justify-content: center !important;
    text-align: center !important;
    padding: 10px 14px !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    border-width: 1px !important;
  }}
  .dot {{
    width: 8px !important;
    height: 8px !important;
  }}
  .sev-Critical {{
    background: var(--crit-bg) !important;
    border-color: rgba(233,75,75,.55) !important;
    color: var(--crit-t) !important;
  }}
  .sev-Critical .dot {{ background: #F05A5A !important; }}
  .sev-High {{
    background: var(--high-bg) !important;
    border-color: rgba(240,138,36,.58) !important;
    color: var(--high-t) !important;
  }}
  .sev-High .dot {{ background: #F59A32 !important; }}
  .sev-Medium {{
    background: var(--med-bg) !important;
    border-color: rgba(224,190,66,.54) !important;
    color: var(--med-t) !important;
  }}
  .sev-Medium .dot {{ background: #E4C54E !important; }}
  .sev-Low {{
    background: var(--low-bg) !important;
    border-color: rgba(76,147,240,.50) !important;
    color: var(--low-t) !important;
  }}
  .sev-Low .dot {{ background: #5A9EFF !important; }}
  .sev-Unknown .dot {{ background: #A7AFB8 !important; }}

  .filter-btn.active-crit {{
    background: var(--crit-bg) !important;
    border-color: rgba(233,75,75,.58) !important;
    color: var(--crit-t) !important;
  }}
  .filter-btn.active-high {{
    background: var(--high-bg) !important;
    border-color: rgba(240,138,36,.58) !important;
    color: var(--high-t) !important;
  }}
  .filter-btn.active-med,
  .filter-btn.active-medi {{
    background: var(--med-bg) !important;
    border-color: rgba(224,190,66,.56) !important;
    color: var(--med-t) !important;
  }}
  .filter-btn.active-low {{
    background: var(--low-bg) !important;
    border-color: rgba(76,147,240,.52) !important;
    color: var(--low-t) !important;
  }}
  .filter-btn.active-unkn {{
    background: var(--unknown-bg) !important;
    border-color: rgba(138,144,154,.44) !important;
    color: var(--unknown-t) !important;
  }}

  /* Sidebar refinement */
  .detail-pane {{
    width: 440px !important;
    padding: 28px 30px !important;
  }}
  .detail-pane .detail-title {{
    font-size: 18px !important;
    font-weight: 600 !important;
    line-height: 1.35 !important;
    margin-bottom: 10px !important;
  }}
  .detail-pane .detail-id {{
    font-size: 16px !important;
    font-weight: 500 !important;
    color: var(--sidebar-accent) !important;
    margin-bottom: 18px !important;
  }}
  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    font-size: 18px !important;
    font-weight: 600 !important;
    min-width: 160px !important;
    padding: 10px 16px !important;
  }}
  .detail-pane .section-label {{
    font-size: 14px !important;
    font-weight: 700 !important;
    letter-spacing: .08em !important;
    color: #F0FBF7 !important;
  }}
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    border: 1px solid var(--sidebar-border) !important;
    background: rgba(255,255,255,.02) !important;
    border-radius: 16px !important;
    min-height: 56px !important;
    padding: 16px 18px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    text-align: center !important;
    font-size: 18px !important;
    font-weight: 500 !important;
    line-height: 1.45 !important;
    color: var(--sidebar-accent) !important;
  }}
  .detail-pane .section p {{
    font-size: 17px !important;
    font-weight: 500 !important;
    line-height: 1.55 !important;
    color: var(--sidebar-accent) !important;
  }}
  .detail-pane .close-btn {{
    font-size: 14px !important;
    font-weight: 600 !important;
  }}

  /* Hyperlink hover */
  a, .detail-pane a {{
    color: var(--sidebar-accent) !important;
    transition: color .15s ease;
  }}
  a:hover, .detail-pane a:hover {{
    color: #4FA3FF !important;
    text-decoration: underline !important;
  }}

  @media (max-width: 1200px) {{
    .filters input {{
      width: 240px !important;
      min-width: 240px !important;
    }}
    .filter-btn {{
      min-width: 78px !important;
      font-size: 13px !important;
      padding: 8px 10px !important;
    }}
    .table-head,
    .row {{
      grid-template-columns: 116px 130px minmax(240px, 1fr) 170px !important;
      gap: 14px !important;
    }}
  }}
</style>


<style id="final-filter-collision-fix">
  /* Final filter layout fix: compact, single-line, no collision */
  .filters {{
    display: grid !important;
    grid-template-columns: 280px minmax(430px, 1fr) minmax(330px, .72fr) !important;
    align-items: center !important;
    column-gap: 12px !important;
    row-gap: 0 !important;
    overflow: visible !important;
    padding: 12px !important;
  }}

  .filters input {{
    width: 100% !important;
    min-width: 0 !important;
    height: 48px !important;
    min-height: 48px !important;
    padding: 0 16px !important;
    font-size: 15px !important;
    border-radius: 14px !important;
  }}

  .filter-group {{
    min-width: 0 !important;
    width: 100% !important;
    height: 48px !important;
    min-height: 48px !important;
    display: flex !important;
    flex-wrap: nowrap !important;
    align-items: center !important;
    justify-content: flex-start !important;
    gap: 8px !important;
    padding: 7px 12px !important;
    overflow: hidden !important;
    border-radius: 14px !important;
  }}

  .filter-label {{
    flex: 0 0 auto !important;
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .04em !important;
    margin-right: 4px !important;
    white-space: nowrap !important;
  }}

  .filter-btn {{
    flex: 0 1 auto !important;
    min-width: auto !important;
    width: auto !important;
    padding: 8px 10px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: .035em !important;
    line-height: 1 !important;
    white-space: nowrap !important;
  }}

  .filter-btn.active {{
    padding-left: 14px !important;
    padding-right: 14px !important;
  }}

  /* Keep TYPE group readable in tighter sidebar-open state */
  .filter-group:nth-of-type(2) .filter-btn {{
    padding-left: 9px !important;
    padding-right: 9px !important;
  }}

  @media (max-width: 1320px) {{
    .filters {{
      grid-template-columns: 250px minmax(390px, 1fr) minmax(300px, .72fr) !important;
      column-gap: 10px !important;
    }}
    .filter-group {{ gap: 6px !important; padding-left: 10px !important; padding-right: 10px !important; }}
    .filter-label {{ font-size: 12px !important; margin-right: 2px !important; }}
    .filter-btn {{ font-size: 11px !important; padding-left: 8px !important; padding-right: 8px !important; }}
  }}

  @media (max-width: 1120px) {{
    .filters {{
      overflow-x: auto !important;
      scrollbar-width: thin;
      grid-template-columns: 240px 430px 340px !important;
    }}
  }}
</style>


<style id="final-sidebar-pill-text-tuning">
  /* Match sidebar severity/type pills to the main pill size */
  .detail-pane .sev-badge,
  .detail-pane .type-badge {{
    min-width: 118px !important;
    height: 38px !important;
    padding: 8px 14px !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    line-height: 1 !important;
    justify-content: center !important;
    text-align: center !important;
    border-radius: 999px !important;
  }}

  .detail-pane .dot {{
    width: 8px !important;
    height: 8px !important;
  }}

  /* Sidebar body text: smaller, white, and not bold */
  .detail-pane .section p,
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    color: rgba(255,255,255,.92) !important;
    font-size: 16px !important;
    font-weight: 400 !important;
    line-height: 1.55 !important;
  }}

  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    min-height: 52px !important;
    padding: 13px 16px !important;
    border: 1px solid rgba(141,214,196,.26) !important;
    background: rgba(255,255,255,.018) !important;
    text-align: center !important;
  }}

  /* Keep labels readable but not oversized */
  .detail-pane .section-label {{
    font-size: 13px !important;
    font-weight: 700 !important;
    color: rgba(255,255,255,.88) !important;
  }}

  .detail-pane .detail-id {{
    color: rgba(255,255,255,.76) !important;
    font-size: 15px !important;
    font-weight: 400 !important;
  }}

  /* Make reference link clearer and larger */
  .detail-pane a {{
    color: #8DD6C4 !important;
    font-size: 17px !important;
    font-weight: 500 !important;
    line-height: 1.45 !important;
    word-break: break-word !important;
  }}

  .detail-pane a:hover {{
    color: #4FA3FF !important;
    text-decoration: underline !important;
  }}
</style>


<style id="final-responsive-fit-fix">
  /* Responsive fit fix: cards, filters, and table */
  .cards {{
    grid-template-columns: repeat(auto-fit, minmax(112px, 1fr)) !important;
    gap: 12px !important;
  }}
  .card {{
    padding: 14px 12px !important;
    min-height: 86px !important;
  }}
  .card-num {{
    font-size: clamp(24px, 2.2vw, 32px) !important;
  }}
  .card-label {{
    font-size: clamp(11px, .9vw, 13px) !important;
    line-height: 1.2 !important;
  }}

  .filters {{
    display: grid !important;
    grid-template-columns: minmax(220px, 300px) minmax(410px, 1fr) minmax(320px, .9fr) !important;
    gap: 12px !important;
    align-items: stretch !important;
    overflow: visible !important;
  }}
  .filters > * {{
    min-width: 0 !important;
  }}
  .filters input {{
    width: 100% !important;
    min-width: 0 !important;
    height: 52px !important;
    font-size: 15px !important;
  }}
  .filter-group {{
    width: 100% !important;
    min-width: 0 !important;
    display: flex !important;
    flex-wrap: wrap !important;
    align-content: center !important;
    row-gap: 8px !important;
    column-gap: 9px !important;
    padding: 10px 12px !important;
  }}
  .filter-label {{
    flex: 0 0 auto !important;
    font-size: 14px !important;
    line-height: 1 !important;
  }}
  .filter-btn {{
    min-width: 68px !important;
    padding: 8px 10px !important;
    font-size: 12px !important;
    line-height: 1 !important;
  }}

  .table-head,
  .row {{
    grid-template-columns: minmax(104px, .8fr) minmax(116px, .9fr) minmax(260px, 2.8fr) minmax(130px, 1fr) !important;
    gap: 12px !important;
  }}
  .table-head {{
    padding: 12px 16px !important;
  }}
  .table-head span {{
    font-size: 11px !important;
    line-height: 1.2 !important;
  }}
  .row {{
    padding: 16px 16px !important;
    min-height: 68px !important;
  }}
  .row-title {{
    font-size: 16px !important;
    line-height: 1.3 !important;
    font-weight: 600 !important;
  }}
  .row-cat,
  .row-res {{
    font-size: 13px !important;
    line-height: 1.35 !important;
  }}
  .sev-badge,
  .type-badge {{
    min-width: 102px !important;
    padding: 8px 10px !important;
    font-size: 12px !important;
    line-height: 1 !important;
  }}

  @media (max-width: 1260px) {{
    .list-pane {{
      padding: 22px 20px 28px !important;
    }}
    .cards {{
      grid-template-columns: repeat(auto-fit, minmax(104px, 1fr)) !important;
      gap: 10px !important;
    }}
    .filters {{
      grid-template-columns: 1fr !important;
    }}
    .filters input {{
      height: 50px !important;
    }}
    .filter-group {{
      min-height: 50px !important;
    }}
    .filter-btn {{
      min-width: 72px !important;
      font-size: 12px !important;
    }}
  }}

  @media (max-width: 980px) {{
    .cards {{
      grid-template-columns: repeat(auto-fit, minmax(96px, 1fr)) !important;
    }}
    .card {{
      min-height: 78px !important;
      border-radius: 12px !important;
    }}
    .table-head,
    .row {{
      grid-template-columns: minmax(96px, .9fr) minmax(108px, 1fr) minmax(220px, 2.4fr) !important;
    }}
    .table-head span:nth-child(4),
    .row > div:nth-child(4) {{
      display: none !important;
    }}
    .row-title {{
      font-size: 15px !important;
    }}
  }}

  @media (max-width: 680px) {{
    .header {{
      padding: 18px 20px !important;
    }}
    .cards {{
      grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
    }}
    .filters {{
      padding: 10px !important;
    }}
    .filter-group {{
      border-radius: 14px !important;
    }}
    .filter-btn {{
      min-width: 64px !important;
      font-size: 11px !important;
      padding: 8px 9px !important;
    }}
    .table-head {{
      display: none !important;
    }}
    .row {{
      grid-template-columns: 1fr !important;
      gap: 8px !important;
      padding: 15px !important;
    }}
    .sev-badge,
    .type-badge {{
      min-width: 100px !important;
    }}
  }}
</style>


<style id="filter-best-fit-final">
  /* Best-fit correction for filter wrapping/collision */
  .filters {{
    display: grid !important;
    grid-template-columns: minmax(180px, 260px) minmax(390px, 1fr) minmax(330px, .78fr) !important;
    align-items: center !important;
    gap: 10px !important;
    padding: 10px 12px !important;
    overflow-x: auto !important;
    overflow-y: hidden !important;
    scrollbar-width: thin;
  }}

  .filters input {{
    width: 100% !important;
    min-width: 0 !important;
    height: 44px !important;
    min-height: 44px !important;
    padding: 10px 14px !important;
    font-size: 14px !important;
    border-radius: 14px !important;
  }}

  .filter-group {{
    min-width: 0 !important;
    width: 100% !important;
    height: 44px !important;
    min-height: 44px !important;
    display: flex !important;
    flex-wrap: nowrap !important;
    align-items: center !important;
    gap: 8px !important;
    padding: 8px 10px !important;
    overflow: hidden !important;
    border-radius: 14px !important;
  }}

  .filter-label {{
    flex: 0 0 auto !important;
    font-size: 13px !important;
    font-weight: 700 !important;
    letter-spacing: .035em !important;
    margin-right: 6px !important;
    line-height: 1 !important;
  }}

  .filter-btn {{
    flex: 0 1 auto !important;
    min-width: auto !important;
    padding: 7px 9px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: .035em !important;
    line-height: 1 !important;
    white-space: nowrap !important;
  }}

  .filter-btn.active,
  .filter-btn.active-crit,
  .filter-btn.active-high,
  .filter-btn.active-med,
  .filter-btn.active-medi,
  .filter-btn.active-low,
  .filter-btn.active-unkn {{
    padding-left: 12px !important;
    padding-right: 12px !important;
  }}

  /* Table text slightly smaller for better fit */
  .table-head span {{ font-size: 11px !important; }}
  .row-title {{ font-size: 16px !important; }}
  .row-cat, .row-res {{ font-size: 13px !important; }}
  .sev-badge, .type-badge {{
    font-size: 12px !important;
    min-width: 104px !important;
    padding: 8px 10px !important;
  }}

  /* Sidebar text -2px as requested, without affecting layout */
  .detail-pane .detail-title {{ font-size: 16px !important; }}
  .detail-pane .detail-id {{ font-size: 14px !important; }}
  .detail-pane .section-label {{ font-size: 12px !important; }}
  .detail-pane .section p,
  .detail-pane .code-block,
  .detail-pane .risk-block,
  .detail-pane .fix-block,
  .detail-pane .warn-block {{
    font-size: 15px !important;
    font-weight: 400 !important;
  }}

  @media (max-width: 1250px) {{
    .filters {{
      grid-template-columns: minmax(170px, 250px) minmax(360px, 1fr) minmax(300px, .74fr) !important;
      gap: 8px !important;
    }}
    .filter-group {{ gap: 6px !important; padding-left: 9px !important; padding-right: 9px !important; }}
    .filter-label {{ font-size: 12px !important; margin-right: 4px !important; }}
    .filter-btn {{ font-size: 11px !important; padding: 6px 7px !important; }}
    .filter-btn.active,
    .filter-btn.active-crit,
    .filter-btn.active-high,
    .filter-btn.active-med,
    .filter-btn.active-medi,
    .filter-btn.active-low,
    .filter-btn.active-unkn {{
      padding-left: 10px !important;
      padding-right: 10px !important;
    }}
  }}

  @media (max-width: 1050px) {{
    .filters {{
      grid-template-columns: 220px 480px 360px !important;
    }}
  }}
</style>


<style id="search-textbox-minus3-only">
  /* Only the search textbox was adjusted */
  .filters {{
    grid-template-columns: minmax(150px, 230px) minmax(390px, 1fr) minmax(330px, .78fr) !important;
  }}
  .filters input#search {{
    height: 41px !important;
    min-height: 41px !important;
    font-size: 11px !important;
    padding: 8px 12px !important;
    border-radius: 13px !important;
  }}
</style>

</head>
<body>
<div class="header">
  <div class="logo">
    <div class="logo-icon">
      <svg width="20" height="20" viewBox="0 0 510 522" xmlns="http://www.w3.org/2000/svg">
        <path d="M382.5 315.169 382.5 153C382.5 138.916 371.084 127.5 357 127.5L355.717 127.5C348.955 127.5 342.47 130.189 337.689 134.97L134.97 337.689C130.189 342.47 127.5 348.955 127.5 355.717L127.5 521.461 0 521.461 0 355.717C0.000274523 315.139 16.1189 276.222 44.8118 247.53L247.53 44.8118C276.222 16.1189 315.139 0.000272506 355.717 0L357 0C441.499 0 510 68.5004 510 153L510 315.169C510 399.668 441.499 468.169 357 468.169L195.691 468.169 195.691 340.669 357 340.669C371.084 340.669 382.5 329.252 382.5 315.169Z" fill="#18E299"/>
      </svg>
    </div>
    <div>
      <div class="logo-name">gitsec</div>
      <div class="logo-sub">security posture report</div>
    </div>
  </div>
  <div class="meta" id="meta-info">—</div>
</div>
<div class="main">
  <div class="list-pane">
    <div class="cards" id="cards"></div>
    <div class="filters">
      <input id="search" placeholder="search findings..." oninput="applyFilters()"/>
      <div class="filter-group">
        <span class="filter-label">Severity:</span>
        <button class="filter-btn active" data-sev="All"      onclick="setSev(this)">All</button>
        <button class="filter-btn"        data-sev="Critical" onclick="setSev(this)">Critical</button>
        <button class="filter-btn"        data-sev="High"     onclick="setSev(this)">High</button>
        <button class="filter-btn"        data-sev="Medium"   onclick="setSev(this)">Medium</button>
        <button class="filter-btn"        data-sev="Low"      onclick="setSev(this)">Low</button>
        <button class="filter-btn"        data-sev="Unknown"  onclick="setSev(this)">Unknown</button>
      </div>
      <div class="filter-group">
        <span class="filter-label">Type:</span>
        <button class="filter-btn active" data-type="All"        onclick="setType(this)">All</button>
        <button class="filter-btn"        data-type="check"      onclick="setType(this)">Check</button>
        <button class="filter-btn"        data-type="dependency" onclick="setType(this)">Dependency</button>
        <button class="filter-btn"        data-type="secret"     onclick="setType(this)">Secret</button>
      </div>
    </div>
    <div class="result-count" id="result-count"></div>
    <div class="table">
      <div class="table-head">
        <span>Severity</span><span>Type</span><span>Finding</span><span>Resource</span>
      </div>
      <div id="rows"></div>
    </div>
  </div>
  <div class="detail-pane" id="detail">
    <button class="close-btn" onclick="closeDetail()">← close</button>
    <div id="detail-content"></div>
  </div>
</div>
<script>
const REPORT = {data_json};
let activeSev = 'All', activeType = 'All', selectedIdx = null;

document.addEventListener('DOMContentLoaded', () => {{
  renderCards();
  applyFilters();
  document.getElementById('meta-info').textContent =
    REPORT.findings.length + ' findings · ' + new Date().toLocaleDateString('en-GB');
}});

function renderCards() {{
  const s = REPORT.summary;
  const sevColors = {{Critical:'var(--crit)',High:'#0F5C3E',Medium:'var(--accent-dim)',Low:'#8FE6C4'}};
  const typeColors = {{check:'#0F5C3E',dependency:'var(--accent)',secret:'#8FE6C4'}};
  const typeLabels = {{check:'Checks',dependency:'Dep CVEs',secret:'Secrets'}};
  let html = `<div class="card" style="border-top:3px solid rgba(255,255,255,.86)">
    <div class="card-num">${{s.total}}</div>
    <div class="card-label">Total</div></div>`;
  for (const [sev, color] of Object.entries(sevColors)) {{
    html += `<div class="card" style="border-top:3px solid rgba(255,255,255,.86)">
      <div class="card-num">${{s.by_severity[sev]||0}}</div>
      <div class="card-label">${{sev}}</div></div>`;
  }}
  for (const [type, label] of Object.entries(typeLabels)) {{
    html += `<div class="card" style="border-top:3px solid rgba(255,255,255,.86)">
      <div class="card-num">${{s.by_type[type]||0}}</div>
      <div class="card-label">${{label}}</div></div>`;
  }}
  for (const [sev, count] of Object.entries(s.by_severity)) {{
    if (sev in sevColors) continue;
    html += `<div class="card" style="border-top:3px solid rgba(255,255,255,.86)">
      <div class="card-num">${{count}}</div>
      <div class="card-label">${{sev}}</div></div>`;
  }}
  document.getElementById('cards').innerHTML = html;
}}

function setSev(btn) {{
  activeSev = btn.dataset.sev;
  document.querySelectorAll('[data-sev]').forEach(b => b.className = 'filter-btn');
  btn.classList.add(activeSev === 'All' ? 'active' : 'active-' + activeSev.toLowerCase().slice(0,4));
  applyFilters();
}}

function setType(btn) {{
  activeType = btn.dataset.type;
  document.querySelectorAll('[data-type]').forEach(b => b.className = 'filter-btn');
  btn.classList.add('active');
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  const filtered = REPORT.findings.filter(f => {{
    if (activeSev  !== 'All' && f.severity !== activeSev)  return false;
    if (activeType !== 'All' && f.type     !== activeType) return false;
    if (q && !((f.title||'').toLowerCase().includes(q) ||
               (f.resource||'').toLowerCase().includes(q) ||
               (f.category||'').toLowerCase().includes(q))) return false;
    return true;
  }});
  document.getElementById('result-count').textContent =
    'showing ' + filtered.length + ' of ' + REPORT.findings.length + ' findings';
  renderRows(filtered);
}}

function renderRows(findings) {{
  if (!findings.length) {{
    document.getElementById('rows').innerHTML = '<div class="empty">no findings match the current filters</div>';
    return;
  }}
  const dots = {{Critical:'rgba(255,255,255,.85)',High:'rgba(26,18,0,.55)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'}};
  document.getElementById('rows').innerHTML = findings.map(f => {{
    const origIdx = REPORT.findings.indexOf(f);
    const sel = selectedIdx === origIdx ? 'selected' : '';
    const dot = `<span class="dot" style="background:${{dots[f.severity]||dots.Info}}"></span>`;
    return `<div class="row ${{sel}}" onclick="openDetail(${{origIdx}})">
      <div><span class="sev-badge sev-${{f.severity}}">${{dot}}${{f.severity}}</span></div>
      <div><span class="type-badge type-${{f.type}}">${{f.type}}</span></div>
      <div>
        <div class="row-title">${{esc(f.title)}}</div>
        ${{f.category ? `<div class="row-cat">${{esc(f.category)}}</div>` : ''}}
      </div>
      <div class="row-res">${{esc(f.resource)}}</div>
    </div>`;
  }}).join('');
}}

function openDetail(idx) {{
  selectedIdx = idx;
  const f = REPORT.findings[idx];
  const id = f.check_id || f.advisory_id || f.secret_type || '';
  const dots = {{Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'}};
  const dot = `<span class="dot" style="background:${{dots[f.severity]||dots.Info}}"></span>`;
  let html = `
    <div class="detail-badges">
      <span class="sev-badge sev-${{f.severity}}">${{dot}}${{f.severity}}</span>
      <span class="type-badge type-${{f.type}}">${{f.type}}</span>
    </div>
    <div class="detail-title">${{esc(f.title)}}</div>
    <div class="detail-id">${{esc(id)}}</div>
    <div class="section">
      <div class="section-label">Resource</div>
      <div class="code-block" style="color:var(--accent-dim)">${{esc(f.resource)}}</div>
    </div>
    <div class="section">
      <div class="section-label">Evidence</div>
      <div class="code-block" style="color:var(--crit-t)">${{esc(f.evidence)}}</div>
    </div>`;
  if (f.description) html += `<div class="section"><div class="section-label">What this means</div><p>${{esc(f.description)}}</p></div>`;
  if (f.risk)        html += `<div class="section"><div class="section-label">Risk</div><div class="risk-block">${{esc(f.risk)}}</div></div>`;
  if (f.remediation) html += `<div class="section"><div class="section-label">How to fix it</div><div class="fix-block">${{esc(f.remediation)}}</div></div>`;
  if (f.type === 'dependency') html += `
    <div class="section"><div class="section-label">Package</div>
    <div class="code-block">${{esc(f.package)}}@${{esc(f.version)}} (${{esc(f.ecosystem)}})</div></div>
    <div class="section"><div class="section-label">CVSS Score</div>
    <div class="code-block" style="color:var(--high-t)">${{esc(String(f.cvss_score))}}</div></div>`;
  if (f.type === 'secret') html += `
    <div class="section"><div class="section-label">File</div>
    <div class="code-block">${{esc(f.file_path)}}${{f.line_number ? ':'+f.line_number : ''}}</div></div>
    <div class="warn-block">⚠ Rotate this credential immediately.</div>`;
  if (f.reference_url) html += `
    <div class="section" style="margin-top:16px"><div class="section-label">Reference</div>
    <a href="${{esc(f.reference_url)}}" target="_blank">${{esc(f.reference_url)}}</a></div>`;
  document.getElementById('detail-content').innerHTML = html;
  document.getElementById('detail').classList.add('open');
  applyFilters();
}}

function closeDetail() {{
  selectedIdx = null;
  document.getElementById('detail').classList.remove('open');
  applyFilters();
}}

function esc(s) {{
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
</script>
</body>
</html>"""