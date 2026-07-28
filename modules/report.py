"""
modules/report.py
─────────────────
Unified Reporting Engine for ARDF.
Generates a self-contained single-file HTML report from session findings.

Report sections
───────────────
  1.  Executive Summary      — AI-generated (Qwen2.5) + stats
  2.  Risk Overview          — severity breakdown + risk score gauge
  3.  Attack Surface Map     — subdomains / hosts / ports discovered
  4.  Findings Table         — sortable, filterable, grouped by severity
  5.  Kill Chain Timeline    — recon → weaponise → exploit → post-exploit
  6.  Attack Chains          — correlated multi-step attack paths
  7.  IOC Summary            — IPs, domains, hashes, CVEs extracted
  8.  MITRE ATT&CK Map       — technique coverage heatmap
  9.  Remediation Plan       — prioritised action items
  10. Sigma Rules            — auto-generated detection rules (purple mode)
  11. Appendix               — raw module outputs (collapsible)
"""

import json
import time
import html
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from modules.session import Session, Finding, SeverityLevel
from modules.intel   import QwenAnalyst, IOCExtractor
from modules.logger  import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────

SEV_COLOUR = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#3498db",
    "info":     "#95a5a6",
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

MITRE_COLOURS = {
    "T1190": "#e74c3c", "T1059": "#e67e22", "T1078": "#e74c3c",
    "T1021": "#e67e22", "T1558": "#e74c3c", "T1003": "#e74c3c",
    "T1110": "#e67e22", "T1046": "#f1c40f", "T1135": "#f1c40f",
    "T1552": "#e67e22", "T1530": "#e67e22", "T1584": "#f1c40f",
    "T1041": "#e67e22", "T1071": "#f1c40f", "T1053": "#f1c40f",
    "T1548": "#e74c3c",
}


def _sev_badge(sev: str) -> str:
    colour = SEV_COLOUR.get(sev, "#95a5a6")
    return (
        f'<span style="background:{colour};color:#fff;'
        f'padding:2px 8px;border-radius:4px;font-size:11px;'
        f'font-weight:bold;text-transform:uppercase">{html.escape(sev)}</span>'
    )


# ─────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────

_CSS = """
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;
  --border:#30363d;--text:#c9d1d9;--text-dim:#8b949e;
  --accent:#58a6ff;--success:#3fb950;--warn:#d29922;
  --critical:#e74c3c;--high:#e67e22;--medium:#f1c40f;
  --low:#3498db;--info:#95a5a6;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);
     font-family:'Segoe UI',system-ui,sans-serif;
     font-size:14px;line-height:1.6}
/* ── Header ── */
header{background:var(--surface);border-bottom:1px solid var(--border);
       padding:20px 40px;display:flex;align-items:center;
       justify-content:space-between;gap:16px;position:sticky;top:0;z-index:100}
header h1{font-size:20px;color:var(--accent);letter-spacing:.03em}
header .meta{color:var(--text-dim);font-size:12px;text-align:right}
.header-badge{background:var(--surface2);border:1px solid var(--border);
              border-radius:6px;padding:4px 12px;font-size:11px;
              color:var(--text-dim);margin-left:8px}
/* ── Nav ── */
nav{background:var(--surface);border-bottom:1px solid var(--border);
    padding:0 40px;display:flex;gap:0;overflow-x:auto;
    scrollbar-width:none;position:sticky;top:65px;z-index:99}
nav::-webkit-scrollbar{display:none}
nav a{color:var(--text-dim);text-decoration:none;padding:10px 14px;
      display:block;font-size:12px;border-bottom:2px solid transparent;
      white-space:nowrap;transition:color .2s,border-color .2s}
nav a:hover,nav a.active{color:var(--accent);border-color:var(--accent)}
/* ── Layout ── */
main{max-width:1400px;margin:0 auto;padding:32px 40px}
section{margin-bottom:56px;scroll-margin-top:120px}
h2{font-size:17px;color:var(--accent);margin-bottom:16px;
   padding-bottom:8px;border-bottom:1px solid var(--border);
   display:flex;align-items:center;gap:10px}
h2 .section-count{font-size:11px;background:var(--surface2);
                  border:1px solid var(--border);border-radius:10px;
                  padding:2px 8px;color:var(--text-dim);font-weight:400}
h3{font-size:12px;color:var(--text-dim);margin:16px 0 8px;
   text-transform:uppercase;letter-spacing:.06em}
/* ── Cards ── */
.card{background:var(--surface);border:1px solid var(--border);
      border-radius:8px;padding:20px;margin-bottom:16px}
.card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
           gap:16px;margin-bottom:24px}
/* ── Stats ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
           gap:12px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);
      border-radius:8px;padding:14px;text-align:center;
      transition:border-color .2s}
.stat:hover{border-color:var(--accent)}
.stat .num{font-size:30px;font-weight:700;margin:4px 0}
.stat .lbl{font-size:10px;color:var(--text-dim);
           text-transform:uppercase;letter-spacing:.06em}
/* ── Table ── */
.table-wrap{overflow-x:auto;border:1px solid var(--border);
            border-radius:8px;margin-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--surface2);padding:10px 12px;text-align:left;
   border-bottom:2px solid var(--border);color:var(--text-dim);
   font-size:10px;text-transform:uppercase;letter-spacing:.06em;
   position:sticky;top:0;cursor:pointer;white-space:nowrap;
   user-select:none}
th:hover{color:var(--accent)}
th::after{content:' ⇅';opacity:.3;font-size:9px}
th[data-dir=asc]::after{content:' ↑';opacity:1}
th[data-dir=desc]::after{content:' ↓';opacity:1}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
/* ── Risk gauge ── */
.gauge-wrap{display:flex;align-items:center;gap:32px;
            margin-bottom:24px;flex-wrap:wrap}
.gauge{position:relative;width:130px;height:130px;flex-shrink:0}
.gauge canvas{display:block}
.gauge .score{position:absolute;top:50%;left:50%;
              transform:translate(-50%,-50%);
              font-size:24px;font-weight:700;color:var(--text)}
.gauge .label{position:absolute;bottom:-20px;left:50%;
              transform:translateX(-50%);font-size:10px;
              color:var(--text-dim);text-transform:uppercase;
              letter-spacing:.06em;white-space:nowrap}
/* ── Bar chart ── */
.bar-chart{display:flex;flex-direction:column;gap:8px;flex:1;min-width:200px}
.bar-row{display:flex;align-items:center;gap:10px}
.bar-label{width:72px;font-size:11px;color:var(--text-dim);
           text-align:right;text-transform:capitalize}
.bar-track{flex:1;background:var(--surface2);border-radius:4px;
           height:18px;overflow:hidden;border:1px solid var(--border)}
.bar-fill{height:100%;border-radius:3px;
          transition:width 1.2s cubic-bezier(.4,0,.2,1);width:0}
.bar-count{width:32px;font-size:11px;color:var(--text-dim);
           font-variant-numeric:tabular-nums}
/* ── Filter bar ── */
.filter-bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;
            align-items:center}
.filter-btn{padding:4px 12px;border:1px solid var(--border);
            border-radius:16px;background:transparent;color:var(--text-dim);
            cursor:pointer;font-size:11px;transition:all .18s}
.filter-btn:hover,.filter-btn.active{color:#000;font-weight:600}
.search-box{background:var(--surface);border:1px solid var(--border);
            border-radius:6px;padding:6px 12px;color:var(--text);
            font-size:12px;width:220px;outline:none;margin-left:auto}
.search-box:focus{border-color:var(--accent)}
/* ── Tags ── */
.tag{display:inline-block;background:var(--surface2);
     border:1px solid var(--border);border-radius:3px;
     padding:1px 5px;font-size:9px;color:var(--text-dim);margin:1px}
/* ── Timeline ── */
.timeline{position:relative;padding-left:24px;
          border-left:2px solid var(--border)}
.tl-item{position:relative;margin-bottom:18px}
.tl-dot{position:absolute;left:-31px;top:5px;width:12px;
        height:12px;border-radius:50%;border:2px solid var(--bg)}
.tl-time{font-size:10px;color:var(--text-dim);margin-bottom:2px}
.tl-title{font-weight:600;margin-bottom:2px;font-size:13px}
.tl-body{font-size:11px;color:var(--text-dim)}
/* ── Attack chains ── */
.chain-card{background:var(--surface);border:1px solid var(--border);
            border-radius:8px;padding:16px;margin-bottom:12px;
            border-left:3px solid var(--critical)}
.chain-card.high{border-left-color:var(--high)}
.chain-card.medium{border-left-color:var(--medium)}
.chain-name{font-weight:700;font-size:14px;margin-bottom:4px}
.chain-meta{font-size:11px;color:var(--text-dim);margin-bottom:8px}
.chain-mitre{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.mitre-tag{padding:2px 8px;border-radius:3px;font-size:10px;
           font-weight:600;color:#fff;font-family:monospace}
/* ── IOC grid ── */
.ioc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
          gap:16px}
.ioc-card h3{margin-top:0;font-size:12px;color:var(--accent);
             margin-bottom:8px}
.ioc-card ul{list-style:none;font-size:11px;color:var(--text-dim)}
.ioc-card ul li{padding:3px 0;border-bottom:1px solid var(--border);
                font-family:monospace;word-break:break-all}
/* ── MITRE heatmap ── */
.mitre-grid{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.mitre-cell{padding:6px 10px;border-radius:4px;font-size:10px;
            font-family:monospace;font-weight:600;color:#fff;
            cursor:default;transition:transform .1s}
.mitre-cell:hover{transform:scale(1.05)}
.mitre-cell.hit{opacity:1}
.mitre-cell.miss{background:var(--surface2)!important;
                 color:var(--text-dim);border:1px solid var(--border)}
/* ── Remediation ── */
.rem-item{display:flex;gap:14px;padding:12px 0;
          border-bottom:1px solid var(--border)}
.rem-item:last-child{border-bottom:none}
.rem-prio{font-size:10px;font-weight:700;text-transform:uppercase;
          letter-spacing:.06em;min-width:64px;padding-top:3px;
          flex-shrink:0}
.rem-body .title{font-weight:600;margin-bottom:3px;font-size:13px}
.rem-body .desc{font-size:11px;color:var(--text-dim);line-height:1.5}
/* ── Sigma rules ── */
.sigma-block{background:var(--bg);border:1px solid var(--border);
             border-radius:6px;margin-bottom:12px}
.sigma-header{padding:10px 14px;background:var(--surface);
              border-bottom:1px solid var(--border);border-radius:6px 6px 0 0;
              display:flex;align-items:center;justify-content:space-between;
              cursor:pointer;font-size:12px;font-weight:600}
.sigma-body{padding:14px;font-size:11px;font-family:monospace;
            white-space:pre-wrap;color:var(--text-dim);
            overflow-x:auto;line-height:1.7}
/* ── Appendix ── */
details{border:1px solid var(--border);border-radius:6px;margin-bottom:8px}
summary{padding:10px 14px;cursor:pointer;font-weight:600;
        font-size:12px;background:var(--surface);
        border-radius:6px;list-style:none;
        display:flex;align-items:center;justify-content:space-between}
summary::marker{display:none}
summary::after{content:'▶';font-size:9px;color:var(--text-dim);
               transition:transform .2s}
details[open] summary::after{transform:rotate(90deg)}
details[open] summary{border-radius:6px 6px 0 0;
                       border-bottom:1px solid var(--border)}
details pre{padding:14px;font-size:11px;overflow-x:auto;
            background:var(--bg);border-radius:0 0 6px 6px;
            white-space:pre-wrap;word-break:break-word;
            color:var(--text-dim);max-height:400px;overflow-y:auto}
/* ── Scroll to top ── */
#scroll-top{position:fixed;bottom:24px;right:24px;
            background:var(--accent);color:#000;border:none;
            border-radius:50%;width:40px;height:40px;
            font-size:18px;cursor:pointer;display:none;
            align-items:center;justify-content:center;
            box-shadow:0 4px 12px rgba(0,0,0,.4);z-index:999}
#scroll-top.visible{display:flex}
/* ── Progress bar ── */
.coverage-bar{height:8px;background:var(--surface2);
              border-radius:4px;overflow:hidden;margin:8px 0}
.coverage-fill{height:100%;background:var(--success);
               border-radius:4px;transition:width 1s ease}
/* ── Responsive ── */
@media(max-width:768px){
  main{padding:16px}
  header,nav{padding-left:16px;padding-right:16px}
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .gauge-wrap{flex-direction:column;align-items:flex-start}
  header{flex-direction:column;align-items:flex-start}
}
"""


# ─────────────────────────────────────────────────────────────
# JavaScript
# ─────────────────────────────────────────────────────────────

_JS = r"""
// ── Table sort ────────────────────────────────────────────────
document.querySelectorAll('th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const table = th.closest('table');
    const idx   = [...th.parentElement.children].indexOf(th);
    const asc   = th.dataset.dir !== 'asc';
    [...table.querySelectorAll('tbody tr')].sort((a, b) => {
      const av = a.cells[idx]?.textContent.trim() || '';
      const bv = b.cells[idx]?.textContent.trim() || '';
      return asc
        ? av.localeCompare(bv, undefined, {numeric: true})
        : bv.localeCompare(av, undefined, {numeric: true});
    }).forEach(r => table.querySelector('tbody').appendChild(r));
    table.querySelectorAll('th').forEach(t => delete t.dataset.dir);
    th.dataset.dir = asc ? 'asc' : 'desc';
  });
});

// ── Severity filter ────────────────────────────────────────────
document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {
  btn.addEventListener('click', () => {
    btn.classList.toggle('active');
    applyFilters();
  });
});

document.querySelectorAll('.filter-btn[data-src]').forEach(btn => {
  btn.addEventListener('click', () => {
    btn.classList.toggle('active');
    applyFilters();
  });
});

document.getElementById('finding-search')?.addEventListener('input', applyFilters);

function applyFilters() {
  const activeSev = [...document.querySelectorAll('.filter-btn[data-sev].active')]
    .map(b => b.dataset.sev);
  const activeSrc = [...document.querySelectorAll('.filter-btn[data-src].active')]
    .map(b => b.dataset.src);
  const query = (document.getElementById('finding-search')?.value || '').toLowerCase();

  document.querySelectorAll('tr[data-sev]').forEach(row => {
    const sevOk = activeSev.length === 0 || activeSev.includes(row.dataset.sev);
    const srcOk = activeSrc.length === 0 || activeSrc.includes(row.dataset.src);
    const txtOk = row.textContent.toLowerCase().includes(query);
    row.style.display = (sevOk && srcOk && txtOk) ? '' : 'none';
  });

  const visible = document.querySelectorAll('tr[data-sev]:not([style*="none"])').length;
  const counter = document.getElementById('findings-counter');
  if (counter) counter.textContent = visible + ' findings';
}

// ── Animate bars ───────────────────────────────────────────────
window.addEventListener('load', () => {
  document.querySelectorAll('.bar-fill[data-w]').forEach(b => {
    b.style.width = b.dataset.w + '%';
  });
  document.querySelectorAll('.coverage-fill[data-w]').forEach(b => {
    b.style.width = b.dataset.w + '%';
  });
});

// ── Gauge canvas ───────────────────────────────────────────────
document.querySelectorAll('.gauge canvas').forEach(c => {
  const score = parseInt(c.dataset.score || 0);
  const max   = parseInt(c.dataset.max || 100);
  const ctx   = c.getContext('2d');
  const cx    = c.width / 2, cy = c.height / 2, r = cx - 12;
  const start = Math.PI * 0.75, end = start + Math.PI * 1.5;
  const pct   = Math.min(score / max, 1);
  const colour = pct > 0.7 ? '#e74c3c' : pct > 0.4 ? '#e67e22' : '#3fb950';

  ctx.lineWidth  = 12;
  ctx.lineCap    = 'round';
  ctx.strokeStyle = '#21262d';
  ctx.beginPath();
  ctx.arc(cx, cy, r, start, end);
  ctx.stroke();

  if (pct > 0) {
    ctx.strokeStyle = colour;
    ctx.beginPath();
    ctx.arc(cx, cy, r, start, start + Math.PI * 1.5 * pct);
    ctx.stroke();
  }
});

// ── Nav active highlight on scroll ────────────────────────────
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('nav a[href^="#"]');

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(a => {
        a.classList.toggle('active', a.getAttribute('href') === '#' + entry.target.id);
      });
    }
  });
}, {rootMargin: '-30% 0px -60% 0px'});

sections.forEach(s => observer.observe(s));

// ── Scroll to top ──────────────────────────────────────────────
const scrollBtn = document.getElementById('scroll-top');
window.addEventListener('scroll', () => {
  if (scrollBtn) scrollBtn.classList.toggle('visible', window.scrollY > 400);
});
scrollBtn?.addEventListener('click', () => window.scrollTo({top: 0, behavior: 'smooth'}));

// ── Sigma collapsible ─────────────────────────────────────────
document.querySelectorAll('.sigma-header').forEach(h => {
  h.addEventListener('click', () => {
    const body = h.nextElementSibling;
    body.style.display = body.style.display === 'none' ? 'block' : 'none';
  });
});

// ── Copy to clipboard ─────────────────────────────────────────
document.querySelectorAll('[data-copy]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.copy);
    if (target) {
      navigator.clipboard.writeText(target.textContent);
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = orig, 1500);
    }
  });
});
"""


# ─────────────────────────────────────────────────────────────
# ReportBuilder
# ─────────────────────────────────────────────────────────────

class ReportBuilder:

# ── Add to ReportBuilder class ──────────────────────────────

    # ── Bypass Section ─────────────────────────────────────────

    def _bypass_section(self) -> str:
        """Cloudflare bypass results section."""
        bypass_report = self.session.dir("bypass") / "bypass_report.json"
        if not bypass_report.exists():
            return ""

        try:
            data = json.loads(bypass_report.read_text())
        except Exception:
            return ""

        candidates = data.get("origin_candidates", [])
        techniques = data.get("techniques", {})

        cards = ""
        for tech_name, tech_result in techniques.items():
            success = tech_result.get("success", False)
            ip = tech_result.get("origin_ip", "N/A")
            evidence = tech_result.get("evidence", "")
            status_colour = "#3fb950" if success else "#e74c3c"
            cards += f"""
<div class="card" style="border-left:3px solid {status_colour}">
  <h3 style="margin-top:0">{html.escape(tech_name.replace('_', ' ').title())}</h3>
  <div style="font-size:12px;color:var(--text-dim)">
    Status: <span style="color:{status_colour}">{'✅ Success' if success else '❌ Failed'}</span>
    {' · Origin IP: <code>' + html.escape(ip) + '</code>' if success else ''}
  </div>
  <div style="font-size:11px;color:var(--text-dim);margin-top:4px">
    {html.escape(evidence[:200])}
  </div>
</div>"""

        if not cards:
            return ""

        return f"""
<section id="bypass">
  <h2>Cloudflare Bypass
    <span class="section-count">{len(candidates)} candidates</span>
  </h2>
  {cards}
  {"<div style='margin-top:12px'><strong style='color:var(--accent)'>Origin Candidates:</strong> " + ', '.join('<code>' + html.escape(ip) + '</code>' for ip in candidates[:5]) + "</div>" if candidates else ""}
</section>"""

    # ── Workflow Section ──────────────────────────────────────

    def _workflow_section(self) -> str:
        """Workflow execution results section."""
        workflow_report = self.session.dir("workflow") / "workflow_report.json"
        if not workflow_report.exists():
            return ""

        try:
            data = json.loads(workflow_report.read_text())
        except Exception:
            return ""

        steps = data.get("step_results", {})
        total = data.get("total_steps", 0)
        completed = data.get("completed_steps", 0)
        failed = data.get("failed_steps", 0)

        step_html = ""
        for step_name, step_result in steps.items():
            status = step_result.get("status", "unknown")
            colour = "#3fb950" if status == "success" else "#e74c3c"
            step_html += f"""
<div class="timeline tl-item" style="margin-bottom:12px">
  <div class="tl-dot" style="background:{colour}"></div>
  <div class="tl-title" style="font-size:12px">
    {html.escape(step_name.replace('_', ' ').title())}
    <span style="color:{colour};font-weight:400;font-size:11px"> — {status}</span>
  </div>
  <div style="font-size:11px;color:var(--text-dim)">
    {html.escape(str(step_result.get('result', {}))[:200])}
  </div>
</div>"""

        return f"""
<section id="workflow">
  <h2>Adaptive Workflow
    <span class="section-count">{completed}/{total} steps</span>
  </h2>
  <div class="card">
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
      <div class="stat"><div class="num">{total}</div><div class="lbl">Total Steps</div></div>
      <div class="stat"><div class="num" style="color:#3fb950">{completed}</div><div class="lbl">Completed</div></div>
      <div class="stat"><div class="num" style="color:#e74c3c">{failed}</div><div class="lbl">Failed</div></div>
    </div>
    <div class="timeline" style="border-left-color:var(--border)">{step_html}</div>
  </div>
</section>"""

    # ── Red Team Section ──────────────────────────────────────

    def _redteam_section(self) -> str:
        """Red team orchestration results section."""
        redteam_report = self.session.dir("redteam") / "redteam_report.json"
        if not redteam_report.exists():
            return ""

        try:
            data = json.loads(redteam_report.read_text())
        except Exception:
            return ""

        vectors_executed = data.get("vectors_executed", 0)
        successful = data.get("successful", 0)
        failed = data.get("failed", 0)
        results = data.get("results", {})

        vector_cards = ""
        for v_name, v_result in results.items():
            success = v_result.get("success", False)
            colour = "#3fb950" if success else "#e74c3c"
            res_data = v_result.get("result", {})
            vector_cards += f"""
<div class="card" style="border-left:3px solid {colour};margin-bottom:10px">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <strong>{html.escape(v_name.replace('_', ' ').title())}</strong>
    <span style="color:{colour};font-size:12px">{'✅ Success' if success else '❌ Failed'}</span>
  </div>
  <div style="font-size:11px;color:var(--text-dim);margin-top:4px">
    {html.escape(str(res_data)[:200])}
  </div>
</div>"""

        return f"""
<section id="redteam">
  <h2>Red Team Orchestration
    <span class="section-count">{successful}/{vectors_executed} vectors</span>
  </h2>
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
    <div class="stat"><div class="num">{vectors_executed}</div><div class="lbl">Vectors</div></div>
    <div class="stat"><div class="num" style="color:#3fb950">{successful}</div><div class="lbl">Succeeded</div></div>
    <div class="stat"><div class="num" style="color:#e74c3c">{failed}</div><div class="lbl">Failed</div></div>
  </div>
  {vector_cards}
</section>"""


# ── Update the build() method ──────────────────────────────────

# In the build() method, add these sections to the sections list:

def build(self) -> str:
    # ... existing code ...

    sections = "\n".join(filter(None, [
        self._exec_summary(),
        self._attack_surface(),
        self._bypass_section(),          # NEW
        self._workflow_section(),        # NEW
        self._redteam_section(),         # NEW
        self._findings_table(),
        self._attack_chains(),
        self._kill_chain(),
        self._ioc_section(),
        self._mitre_section(),
        self._remediation_plan(),
        self._sigma_section() if self.purple_mode else "",
        self._appendix(),
    ]))

    # ... rest of build method ...


    def __init__(
        self,
        session:      Session,
        logger:       ARDFLogger,
        purple_mode:  bool = False,
        sigma_rules:  Optional[List[Dict]] = None,
        chains:       Optional[List[Dict]] = None,
        mitre_hits:   Optional[List[str]]  = None,
    ):
        self.session     = session
        self.logger      = logger
        self.purple_mode = purple_mode
        self.sigma_rules = sigma_rules or []
        self.chains      = chains or []
        self.mitre_hits  = mitre_hits or []
        self.findings    = sorted(
            session.get_findings(),
            key=lambda f: SEV_ORDER.get(f.severity.value, 99),
        )
        self.summary     = session.findings_summary()
        self.ai          = QwenAnalyst()
        self.ioc_ext     = IOCExtractor()

    # ── Navigation ────────────────────────────────────────────

    def _nav(self) -> str:
        links = [
            ("summary",     "Summary"),
            ("surface",     "Attack Surface"),
            ("findings",    "Findings"),
            ("chains",      "Attack Chains"),
            ("killchain",   "Kill Chain"),
            ("iocs",        "IOCs"),
            ("mitre",       "MITRE"),
            ("remediation", "Remediation"),
        ]
        if self.purple_mode and self.sigma_rules:
            links.append(("sigma", "Sigma Rules"))
        links.append(("appendix", "Appendix"))
        return "".join(f'<a href="#{a}">{l}</a>' for a, l in links)

    # ── Executive Summary ─────────────────────────────────────

    def _exec_summary(self) -> str:
        ai_text = ""
        try:
            ai_text = self.ai.summarise_session(self.findings)
        except Exception:
            pass
        if not ai_text:
            ai_text = (
                f"Security assessment completed for "
                f"{html.escape(self.session.meta.target)}. "
                f"A total of {len(self.findings)} findings were identified."
            )

        risk      = self.session.meta.risk_score
        gauge_max = max(risk * 1.5, 100)

        stats_html = "".join(
            f'<div class="stat">'
            f'<div class="num" style="color:{SEV_COLOUR.get(sev,"#888")}">{cnt}</div>'
            f'<div class="lbl">{sev}</div></div>'
            for sev, cnt in self.summary.items()
            if cnt > 0
        )
        stats_html += (
            f'<div class="stat">'
            f'<div class="num">{len(self.findings)}</div>'
            f'<div class="lbl">Total</div></div>'
        )
        if self.session.meta.risk_score:
            stats_html += (
                f'<div class="stat">'
                f'<div class="num" style="color:var(--critical)">'
                f'{self.session.meta.risk_score:.0f}</div>'
                f'<div class="lbl">Risk Score</div></div>'
            )

        gauge_html = (
            f'<div class="gauge">'
            f'<canvas width="130" height="130" '
            f'data-score="{risk:.0f}" data-max="{gauge_max:.0f}"></canvas>'
            f'<div class="score">{risk:.0f}</div>'
            f'<div class="label">Risk Score</div>'
            f'</div>'
        )

        total = max(len(self.findings), 1)
        bar_rows = "".join(
            f'<div class="bar-row">'
            f'<span class="bar-label">{sev}</span>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" data-w="{cnt*100//total}" '
            f'style="background:{SEV_COLOUR.get(sev,"#888")}"></div>'
            f'</div>'
            f'<span class="bar-count">{cnt}</span>'
            f'</div>'
            for sev, cnt in self.summary.items()
        )

        # Mode badges
        mode_badge = (
            f'<span class="header-badge" '
            f'style="color:{"#e74c3c" if self.session.meta.mode.value=="red" else "#3fb950" if self.session.meta.mode.value=="blue" else "#9b59b6"}">'
            f'{self.session.meta.mode.value.upper()}</span>'
        )

        return f"""
<section id="summary">
  <h2>Executive Summary {mode_badge}</h2>
  <div class="stat-grid">{stats_html}</div>
  <div class="gauge-wrap">
    {gauge_html}
    <div style="flex:1">
      <h3>Severity Distribution</h3>
      <div class="bar-chart">{bar_rows}</div>
    </div>
    <div style="flex:2;min-width:200px">
      <h3>AI Assessment</h3>
      <div class="card" style="margin-bottom:0">
        <p style="white-space:pre-wrap;font-size:13px">{html.escape(ai_text)}</p>
      </div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:16px">
    <div class="card">
      <h3 style="margin-top:0">Modules Run</h3>
      <div style="font-size:12px;color:var(--text-dim)">
        {', '.join(self.session.meta.modules_done) or 'None recorded'}
      </div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Session Info</h3>
      <div style="font-size:12px;color:var(--text-dim)">
        ID: <code>{html.escape(self.session.meta.session_id)}</code><br>
        Started: {self.session.meta.created_at[:19].replace('T',' ')}<br>
        Target: <strong>{html.escape(self.session.meta.target)}</strong>
      </div>
    </div>
  </div>
</section>"""

    # ── Attack Surface ────────────────────────────────────────

    def _attack_surface(self) -> str:
        hosts = list({
            f.host for f in self.findings
            if f.host and f.host not in ("localhost", "")
        })[:150]

        ports_by_host: Dict[str, List] = {}
        findings_by_host: Dict[str, int] = {}
        for f in self.findings:
            if f.port:
                ports_by_host.setdefault(f.host, []).append(f.port)
            findings_by_host[f.host] = findings_by_host.get(f.host, 0) + 1

        rows = "".join(
            f'<tr>'
            f'<td><code style="font-size:12px">{html.escape(h)}</code></td>'
            f'<td style="font-size:11px;color:var(--text-dim)">'
            f'{", ".join(str(p) for p in sorted(set(ports_by_host.get(h,[]))))[:80]}'
            f'</td>'
            f'<td style="text-align:center">{findings_by_host.get(h,0)}</td>'
            f'</tr>'
            for h in sorted(hosts, key=lambda h: findings_by_host.get(h,0), reverse=True)
        )

        no_data = (
            "<tr><td colspan='3' style='color:var(--text-dim);"
            "text-align:center;padding:20px'>No hosts discovered yet.</td></tr>"
        )

        return f"""
<section id="surface">
  <h2>Attack Surface <span class="section-count">{len(hosts)} hosts</span></h2>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th data-sort>Host / Subdomain</th>
        <th data-sort>Open Ports</th>
        <th data-sort style="text-align:center">Findings</th>
      </tr></thead>
      <tbody>{rows or no_data}</tbody>
    </table>
  </div>
</section>"""

    # ── Findings Table ────────────────────────────────────────

    def _findings_table(self) -> str:
        rows_html = ""
        sources   = sorted({f.source for f in self.findings if f.source})

        for f in self.findings:
            sev  = f.severity.value
            tags = "".join(
                f'<span class="tag">{html.escape(t)}</span>'
                for t in f.tags[:6]
            )
            cve  = f'<code style="font-size:10px">{html.escape(f.cve)}</code>' if f.cve else ""
            evid = html.escape((f.evidence or "")[:100])
            rem  = html.escape((f.remediation or "")[:100])
            desc = ""
            if f.description:
                desc = (
                    f'<br><small style="color:var(--text-dim);font-size:11px">'
                    f'{html.escape(f.description[:120])}</small>'
                )
            rows_html += (
                f'<tr data-sev="{sev}" data-src="{html.escape(f.source)}">'
                f'<td>{_sev_badge(sev)}</td>'
                f'<td>'
                f'<strong style="font-size:13px">{html.escape(f.title)}</strong>'
                f'{desc}'
                f'</td>'
                f'<td>'
                f'<code style="font-size:11px">{html.escape(f.host)}</code>'
                f'{":<code style=font-size:11px>"+str(f.port)+"</code>" if f.port else ""}'
                f'</td>'
                f'<td>{cve}</td>'
                f'<td style="font-size:11px;color:var(--text-dim)">'
                f'{html.escape(f.source)}</td>'
                f'<td>{tags}</td>'
                f'<td style="font-size:11px;color:var(--text-dim)">{evid}</td>'
                f'<td style="font-size:11px">{rem}</td>'
                f'</tr>'
            )

        sev_btns = "".join(
            f'<button class="filter-btn" data-sev="{sev}" '
            f'style="border-color:{SEV_COLOUR[sev]}">'
            f'{sev.upper()} ({self.summary.get(sev,0)})</button>'
            for sev in ["critical","high","medium","low","info"]
        )
        src_btns = "".join(
            f'<button class="filter-btn" data-src="{html.escape(s)}">'
            f'{html.escape(s)}</button>'
            for s in sources
        )

        return f"""
<section id="findings">
  <h2>Findings
    <span class="section-count" id="findings-counter">{len(self.findings)} findings</span>
  </h2>
  <div class="filter-bar">
    {sev_btns}
    <input type="text" class="search-box" id="finding-search"
           placeholder="Search findings…">
  </div>
  {"<div class='filter-bar' style='margin-top:-6px'>"+src_btns+"</div>" if src_btns else ""}
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th data-sort>Severity</th>
        <th data-sort>Title</th>
        <th data-sort>Host:Port</th>
        <th data-sort>CVE</th>
        <th data-sort>Source</th>
        <th>Tags</th>
        <th>Evidence</th>
        <th>Remediation</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</section>"""

    # ── Attack Chains ─────────────────────────────────────────

    def _attack_chains(self) -> str:
        if not self.chains:
            # Try to build basic chains from findings
            from ai.analyst import FindingAnalyst
            try:
                analyst      = FindingAnalyst(self.session, self.logger)
                self.chains  = analyst.find_chains(self.findings)
            except Exception:
                pass

        if not self.chains:
            return f"""
<section id="chains">
  <h2>Attack Chains <span class="section-count">0 detected</span></h2>
  <div class="card" style="color:var(--text-dim);text-align:center;padding:32px">
    No multi-step attack chains detected in current findings.
  </div>
</section>"""

        cards = ""
        for chain in self.chains:
            sev    = chain.get("severity","high")
            colour = SEV_COLOUR.get(sev, "#e67e22")
            mitre_tags = "".join(
                f'<span class="mitre-tag" style="background:{MITRE_COLOURS.get(t,"#444")}">'
                f'{html.escape(t)}</span>'
                for t in chain.get("mitre", [])
            )
            conf = int(chain.get("confidence", 0.5) * 100)
            cards += f"""
<div class="chain-card {sev}">
  <div class="chain-name" style="color:{colour}">{html.escape(chain.get('name',''))}</div>
  <div class="chain-meta">
    Confidence: {conf}% &nbsp;·&nbsp;
    Severity: {_sev_badge(sev)} &nbsp;·&nbsp;
    Matched on: {', '.join(html.escape(m) for m in chain.get('matched_on',[]))}
  </div>
  <div style="font-size:12px;color:var(--text-dim);margin-bottom:8px">
    {html.escape(chain.get('description',''))}
  </div>
  <div class="coverage-bar">
    <div class="coverage-fill" data-w="{conf}"></div>
  </div>
  <div class="chain-mitre">{mitre_tags}</div>
</div>"""

        return f"""
<section id="chains">
  <h2>Attack Chains <span class="section-count">{len(self.chains)} detected</span></h2>
  {cards}
</section>"""

    # ── Kill Chain Timeline ────────────────────────────────────

    def _kill_chain(self) -> str:
        phase_map = {
            "recon.passive":    ("Reconnaissance (Passive)",    "#58a6ff"),
            "recon.normal":     ("Reconnaissance (Active)",     "#58a6ff"),
            "recon.depth":      ("Reconnaissance (Deep)",       "#58a6ff"),
            "intel":            ("Threat Intelligence",         "#d2a679"),
            "exploit.research": ("Weaponisation",               "#e67e22"),
            "exploit.web":      ("Exploitation (Web)",          "#e74c3c"),
            "exploit.network":  ("Exploitation (Network)",      "#e74c3c"),
            "exploit.password": ("Exploitation (Password)",     "#e74c3c"),
            "exploit.post":     ("Post-Exploitation",           "#9b59b6"),
            "defense.network":  ("Network Defense",             "#3fb950"),
            "defense.os":       ("OS Defense",                  "#3fb950"),
            "defense.logs":     ("Log Analysis",                "#3fb950"),
        }

        items = []
        for f in self.findings:
            phase_info = phase_map.get(f.source)
            if not phase_info:
                continue
            phase_label, colour = phase_info
            items.append({
                "ts":     f.timestamp[:19].replace("T", " "),
                "phase":  phase_label,
                "colour": colour,
                "title":  f.title,
                "sev":    f.severity.value,
                "host":   f.host,
            })

        items = items[:50]
        tl_html = ""
        for item in items:
            tl_html += (
                f'<div class="tl-item">'
                f'<div class="tl-dot" style="background:{item["colour"]}"></div>'
                f'<div class="tl-time">{item["ts"]} &nbsp;·&nbsp;'
                f'<span style="color:{item["colour"]}">'
                f'{html.escape(item["phase"])}</span></div>'
                f'<div class="tl-title">{html.escape(item["title"])}</div>'
                f'<div class="tl-body">'
                f'{_sev_badge(item["sev"])} &nbsp;'
                f'<code style="font-size:11px">{html.escape(item["host"])}</code>'
                f'</div></div>'
            )

        empty = (
            "<p style='color:var(--text-dim)'>No timeline data yet.</p>"
            if not tl_html else ""
        )

        return f"""
<section id="killchain">
  <h2>Kill Chain Timeline <span class="section-count">{len(items)} events</span></h2>
  <div class="card timeline">{tl_html or empty}</div>
</section>"""

    # ── IOC Section ───────────────────────────────────────────

    def _ioc_section(self) -> str:
        iocs = self.ioc_ext.extract_from_findings(self.findings)

        intel_report = self.session.dir("intel") / "intel_report.json"
        if intel_report.exists():
            try:
                data = json.loads(intel_report.read_text())
                for k, v in data.get("iocs", {}).items():
                    iocs[k] = list(set(iocs.get(k, []) + v))
            except Exception:
                pass

        labels = {
            "ips":           "IP Addresses",
            "domains":       "Domains",
            "urls":          "URLs",
            "hashes_md5":    "MD5 Hashes",
            "hashes_sha1":   "SHA-1 Hashes",
            "hashes_sha256": "SHA-256 Hashes",
            "cves":          "CVEs",
            "emails":        "Email Addresses",
        }

        total_iocs = sum(len(v) for v in iocs.values())
        cards_html = ""
        for key, label in labels.items():
            items = iocs.get(key, [])
            if not items:
                continue
            li = "".join(
                f'<li title="{html.escape(i)}">'
                f'{html.escape(i[:60])}{"…" if len(i)>60 else ""}'
                f'</li>'
                for i in items[:30]
            )
            more = (
                f'<li style="color:var(--accent);cursor:pointer">'
                f'… and {len(items)-30} more</li>'
                if len(items) > 30 else ""
            )
            cards_html += (
                f'<div class="card ioc-card">'
                f'<h3>{html.escape(label)} '
                f'<span style="color:var(--text-dim);font-weight:400">({len(items)})</span>'
                f'</h3>'
                f'<ul>{li}{more}</ul></div>'
            )

        return f"""
<section id="iocs">
  <h2>Indicators of Compromise
    <span class="section-count">{total_iocs} total</span>
  </h2>
  <div class="ioc-grid">
    {cards_html or "<p style='color:var(--text-dim)'>No IOCs extracted.</p>"}
  </div>
</section>"""

    # ── MITRE ATT&CK Map ──────────────────────────────────────

    def _mitre_section(self) -> str:
        all_techniques = {
            "T1190": "Exploit Public-Facing App",
            "T1059": "Command & Scripting",
            "T1078": "Valid Accounts",
            "T1021": "Remote Services",
            "T1046": "Network Service Scan",
            "T1135": "Network Share Discovery",
            "T1110": "Brute Force",
            "T1558": "Steal Kerberos Tickets",
            "T1003": "OS Credential Dumping",
            "T1552": "Unsecured Credentials",
            "T1530": "Data from Cloud Storage",
            "T1584": "Compromise Infrastructure",
            "T1041": "Exfiltration over C2",
            "T1071": "App Layer Protocol",
            "T1053": "Scheduled Task/Job",
            "T1548": "Abuse Elevation Control",
        }

        # Collect hits from chains + findings tags
        hits = set(self.mitre_hits)
        for chain in self.chains:
            hits.update(chain.get("mitre", []))
        for f in self.findings:
            for tag in f.tags:
                if tag.startswith("T1"):
                    hits.add(tag)

        cells = ""
        for tid, name in all_techniques.items():
            hit     = tid in hits
            colour  = MITRE_COLOURS.get(tid, "#444")
            css     = "hit" if hit else "miss"
            style   = f"background:{colour}" if hit else ""
            title   = f"{tid}: {name}"
            cells += (
                f'<div class="mitre-cell {css}" '
                f'style="{style}" title="{html.escape(title)}">'
                f'{html.escape(tid)}</div>'
            )

        coverage = int(len(hits) / max(len(all_techniques), 1) * 100)

        return f"""
<section id="mitre">
  <h2>MITRE ATT&CK Coverage
    <span class="section-count">{len(hits)}/{len(all_techniques)} techniques</span>
  </h2>
  <div class="card">
    <h3 style="margin-top:0">Technique Coverage</h3>
    <div class="coverage-bar" style="margin-bottom:12px">
      <div class="coverage-fill" data-w="{coverage}"></div>
    </div>
    <div style="font-size:11px;color:var(--text-dim);margin-bottom:16px">
      {coverage}% coverage — {len(hits)} techniques observed
    </div>
    <div class="mitre-grid">{cells}</div>
    <div style="margin-top:12px;font-size:11px;color:var(--text-dim)">
      <span style="display:inline-block;width:12px;height:12px;
             background:#e74c3c;border-radius:2px;margin-right:4px"></span>
      Observed technique &nbsp;&nbsp;
      <span style="display:inline-block;width:12px;height:12px;
             background:var(--surface2);border:1px solid var(--border);
             border-radius:2px;margin-right:4px"></span>
      Not observed
    </div>
  </div>
</section>"""

    # ── Remediation Plan ──────────────────────────────────────

    def _remediation_plan(self) -> str:
        critical = [f for f in self.findings
                    if f.severity == SeverityLevel.CRITICAL and f.remediation]
        high     = [f for f in self.findings
                    if f.severity == SeverityLevel.HIGH and f.remediation]
        medium   = [f for f in self.findings
                    if f.severity == SeverityLevel.MEDIUM and f.remediation]

        items_html = ""
        for sev_label, sev_colour, group in [
            ("CRITICAL", SEV_COLOUR["critical"], critical[:5]),
            ("HIGH",     SEV_COLOUR["high"],     high[:5]),
            ("MEDIUM",   SEV_COLOUR["medium"],   medium[:5]),
        ]:
            for f in group:
                items_html += (
                    f'<div class="rem-item">'
                    f'<div class="rem-prio" style="color:{sev_colour}">'
                    f'{sev_label}</div>'
                    f'<div class="rem-body">'
                    f'<div class="title">{html.escape(f.title)}</div>'
                    f'<div class="desc">{html.escape(f.remediation)}'
                    f'{"  <code style=font-size:10px>"+html.escape(f.cve)+"</code>" if f.cve else ""}'
                    f'</div></div></div>'
                )

        ai_advice = ""
        intel_report = self.session.dir("intel") / "intel_report.json"
        if intel_report.exists():
            try:
                data     = json.loads(intel_report.read_text())
                ai_advice = data.get("ai", {}).get("blue_advice", "")
            except Exception:
                pass

        ai_block = ""
        if ai_advice:
            ai_block = (
                f'<div class="card" style="margin-top:16px">'
                f'<h3 style="margin-top:0">AI Hardening Recommendations</h3>'
                f'<pre style="background:transparent;padding:0;font-size:12px;'
                f'white-space:pre-wrap;color:var(--text)">'
                f'{html.escape(ai_advice)}</pre></div>'
            )

        no_rem = (
            "<p style='color:var(--text-dim)'>No remediation notes recorded yet.</p>"
            if not items_html else ""
        )

        total = len(critical) + len(high) + len(medium)
        return f"""
<section id="remediation">
  <h2>Remediation Plan
    <span class="section-count">{total} items</span>
  </h2>
  <div class="card">{items_html or no_rem}</div>
  {ai_block}
</section>"""

    # ── Sigma Rules (purple mode) ─────────────────────────────

    def _sigma_section(self) -> str:
        if not self.sigma_rules:
            return ""

        blocks = ""
        for i, rule in enumerate(self.sigma_rules):
            rule_id   = f"sigma_{i}"
            rule_yaml = rule.get("sigma_rule", "# No rule generated")
            title     = rule.get("title", f"Detection Rule {i+1}")
            level     = rule.get("level", "medium")
            colour    = SEV_COLOUR.get(level, "#888")
            blocks += (
                f'<div class="sigma-block">'
                f'<div class="sigma-header">'
                f'<span>{html.escape(title)}</span>'
                f'<div style="display:flex;gap:8px;align-items:center">'
                f'{_sev_badge(level)}'
                f'<button data-copy="{rule_id}" style="background:var(--surface2);'
                f'border:1px solid var(--border);color:var(--text-dim);'
                f'border-radius:4px;padding:2px 8px;font-size:10px;cursor:pointer">'
                f'Copy</button>'
                f'</div></div>'
                f'<div class="sigma-body" id="{rule_id}" style="display:none">'
                f'{html.escape(rule_yaml)}'
                f'</div></div>'
            )

        return f"""
<section id="sigma">
  <h2>Sigma Detection Rules
    <span class="section-count">{len(self.sigma_rules)} rules</span>
  </h2>
  <p style="color:var(--text-dim);font-size:12px;margin-bottom:16px">
    Auto-generated Sigma rules for each observed attack technique.
    Import into your SIEM for immediate detection coverage.
  </p>
  {blocks}
</section>"""

    # ── Appendix ──────────────────────────────────────────────

    def _appendix(self) -> str:
        blocks = ""
        for module_dir in sorted(self.session.root.iterdir()):
            if not module_dir.is_dir() or module_dir.name in ("report", "logs"):
                continue
            files = (
                sorted(module_dir.rglob("*.txt")) +
                sorted(module_dir.rglob("*.json"))
            )
            for f in files[:10]:
                try:
                    content = f.read_text(errors="ignore")[:4000]
                    if not content.strip():
                        continue
                    rel = f.relative_to(self.session.root)
                    size = f.stat().st_size
                    size_label = (
                        f"{size // 1024}KB" if size > 1024 else f"{size}B"
                    )
                    blocks += (
                        f'<details>'
                        f'<summary>'
                        f'{html.escape(str(rel))}'
                        f'<span style="color:var(--text-dim);font-size:10px;'
                        f'font-weight:400">{size_label}</span>'
                        f'</summary>'
                        f'<pre>{html.escape(content)}</pre>'
                        f'</details>'
                    )
                except Exception:
                    pass

        return f"""
<section id="appendix">
  <h2>Appendix — Raw Outputs</h2>
  {blocks or "<p style='color:var(--text-dim)'>No raw output files available.</p>"}
</section>"""

    # ── Full page assembly ────────────────────────────────────

    def build(self) -> str:
        m  = self.session.meta
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        sections = "\n".join(filter(None, [
            self._exec_summary(),
            self._attack_surface(),
            self._findings_table(),
            self._attack_chains(),
            self._kill_chain(),
            self._ioc_section(),
            self._mitre_section(),
            self._remediation_plan(),
            self._sigma_section() if self.purple_mode else "",
            self._appendix(),
        ]))

        risk_level = (
            "CRITICAL" if m.risk_score > 70
            else "HIGH" if m.risk_score > 40
            else "MEDIUM" if m.risk_score > 15
            else "LOW"
        )
        risk_colour = SEV_COLOUR.get(risk_level.lower(), "#888")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARDF Report — {html.escape(m.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <div>
    <h1>&#x1F6E1; ARDF Security Report</h1>
    <div class="meta" style="margin-top:4px">
      Target: <strong>{html.escape(m.target)}</strong> &nbsp;·&nbsp;
      Mode: <strong>{m.mode.value.upper()}</strong> &nbsp;·&nbsp;
      Risk: <strong style="color:{risk_colour}">{risk_level}</strong>
      &nbsp;·&nbsp; Generated: {ts}
    </div>
  </div>
  <div style="text-align:right">
    <div style="font-size:11px;color:var(--text-dim)">
      Session: <code>{html.escape(m.session_id)}</code>
    </div>
    <div style="font-size:11px;color:var(--text-dim);margin-top:4px">
      Findings: <strong>{len(self.findings)}</strong> &nbsp;·&nbsp;
      Risk Score: <strong style="color:{risk_colour}">{m.risk_score:.0f}</strong>
    </div>
  </div>
</header>
<nav>{self._nav()}</nav>
<main>{sections}</main>
<button id="scroll-top" title="Back to top">↑</button>
<script>{_JS}</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def generate_report(
    session:      Session,
    logger:       Optional[ARDFLogger] = None,
    open_browser: bool = False,
    purple_mode:  bool = False,
    sigma_rules:  Optional[List[Dict]] = None,
    chains:       Optional[List[Dict]] = None,
    mitre_hits:   Optional[List[str]]  = None,
) -> Path:
    """
    Build the HTML report and save it to the session report directory.

    Args:
        session      : active Session object
        logger       : ARDFLogger instance
        open_browser : open report in default browser after generation
        purple_mode  : include sigma rules and blue team sections
        sigma_rules  : list of sigma rule dicts (purple mode)
        chains       : pre-computed attack chains (optional)
        mitre_hits   : list of MITRE technique IDs observed

    Returns:
        Path to the generated .html file
    """
    if logger is None:
        logger = get_logger("report")

    logger.banner("REPORT GENERATION", style="bold magenta")

    builder      = ReportBuilder(
        session     = session,
        logger      = logger,
        purple_mode = purple_mode,
        sigma_rules = sigma_rules or [],
        chains      = chains or [],
        mitre_hits  = mitre_hits or [],
    )
    html_content = builder.build()

    report_dir   = session.dir("report")
    report_path  = report_dir / f"ardf_report_{session.meta.session_id}.html"
    report_path.write_text(html_content, encoding="utf-8")

    size_kb = report_path.stat().st_size // 1024
    logger.success(
        f"Report saved → {report_path} "
        f"({size_kb} KB | findings={len(builder.findings)})"
    )

    if open_browser:
        try:
            import webbrowser
            webbrowser.open(report_path.as_uri())
        except Exception:
            pass

    session.mark_module_done("report")
    return report_path
