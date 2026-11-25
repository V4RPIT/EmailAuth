"""FastAPI web dashboard and REST API for EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1.

Provides:
- Interactive dark-mode Security Operations Center (SOC) Web UI at `GET /`
- Raw Email & Header Analyzer endpoint `POST /api/analyze`
- Outbound DKIM Signing endpoint `POST /api/sign`
- Controlled DNS Zone & DMARC Policy Lifecycle endpoints `GET /api/dns`, `POST /api/dmarc/policy`
- Pre-built sample loader `GET /api/samples`
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

_PKG_ROOT = Path(__file__).resolve().parent
if str(_PKG_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT.parent))

from email_auth_gateway.src.config import (  # noqa: E402
    BIND_ZONE_PATH,
    DNS_ZONE_PATH,
    SAMPLES_DIR,
    GatewayConfig,
)
from email_auth_gateway.src.dns_store import DNSZoneStore  # noqa: E402
from email_auth_gateway.src.gateway import SecureEmailGateway  # noqa: E402
from email_auth_gateway.src.header_parser import analyze_raw_email  # noqa: E402


app = FastAPI(
    title="EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1",
    description="Analyze raw email headers, inspect DNS authentication records, sign outbound mail, and manage DMARC policy rollout.",
    version="1.0.0",
)


def _get_gateway() -> SecureEmailGateway:
    store = DNSZoneStore(zone_path=DNS_ZONE_PATH)
    gw = SecureEmailGateway(config=GatewayConfig(), dns_store=store)
    if not gw.dns_store.get_spf(gw.config.domain):
        gw.provision_domain(regenerate_keys=False, initial_dmarc_policy="none")
    return gw


class AnalyzeRequest(BaseModel):
    raw_email: str = Field(..., min_length=1, description="Raw RFC 5322 email or header block")
    client_ip: Optional[str] = Field(default=None, description="Optional explicit client IP")
    mail_from: Optional[str] = Field(default=None, description="Optional explicit envelope MAIL FROM")
    allow_live_dns: bool = Field(default=False, description="Allow live UDP DNS TXT lookup fallback")


class SignRequest(BaseModel):
    sender: str = Field(default="notifications@securemail.example")
    recipient: str = Field(default="alice@partner.example")
    subject: str = Field(default="Authenticated Security Notice")
    body: str = Field(default="This message is cryptographically signed with RSA-2048 DKIM.")


class DMARCPolicyRequest(BaseModel):
    policy: str = Field(..., pattern="^(none|quarantine|reject)$")
    adkim: str = Field(default="r", pattern="^(r|s)$")
    aspf: str = Field(default="r", pattern="^(r|s)$")
    pct: int = Field(default=100, ge=0, le=100)


@app.get("/api/health")
def health() -> Dict[str, Any]:
    gw = _get_gateway()
    return {
        "status": "healthy",
        "domain": gw.config.domain,
        "selector": gw.config.dkim_selector,
        "dmarc_record": gw.dns_store.get_dmarc(gw.config.domain),
    }


@app.get("/api/dns")
def get_dns_records() -> Dict[str, Any]:
    gw = _get_gateway()
    return {
        "domain": gw.config.domain,
        "records": gw.dns_store.records,
        "bind_zone": gw.dns_store.export_bind_zone(gw.config.domain),
    }


@app.post("/api/dmarc/policy")
def update_dmarc_policy(req: DMARCPolicyRequest) -> Dict[str, Any]:
    gw = _get_gateway()
    result = gw.lifecycle.transition_policy(
        target_policy=req.policy,
        adkim=req.adkim,
        aspf=req.aspf,
        pct=req.pct,
        force=True,
    )
    gw.dns_store.save()
    BIND_ZONE_PATH.write_text(gw.dns_store.export_bind_zone(gw.config.domain), encoding="utf-8")
    return result


@app.post("/api/sign")
def sign_outgoing_email(req: SignRequest) -> Dict[str, Any]:
    gw = _get_gateway()
    signed_eml = gw.compose_and_sign(
        sender=req.sender,
        recipient=req.recipient,
        subject=req.subject,
        body=req.body,
    )
    return {"signed_email": signed_eml}


@app.post("/api/analyze")
def analyze_email_endpoint(req: AnalyzeRequest) -> Dict[str, Any]:
    store = DNSZoneStore(zone_path=DNS_ZONE_PATH, allow_live_dns=req.allow_live_dns)
    if not store.get_spf(GatewayConfig().domain):
        gw = SecureEmailGateway(config=GatewayConfig(), dns_store=store)
        gw.provision_domain(regenerate_keys=False, initial_dmarc_policy="none")
    analysis = analyze_raw_email(
        raw_input=req.raw_email,
        dns_store=store,
        client_ip=req.client_ip or None,
        mail_from=req.mail_from or None,
    )
    return analysis.to_dict()


@app.get("/api/samples")
def list_samples() -> Dict[str, List[Dict[str, str]]]:
    samples: List[Dict[str, str]] = []
    if SAMPLES_DIR.exists():
        for eml_file in sorted(SAMPLES_DIR.glob("*.eml")):
            samples.append(
                {
                    "name": eml_file.stem,
                    "filename": eml_file.name,
                    "content": eml_file.read_bytes().decode("utf-8"),
                }
            )
    return {"samples": samples}


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #121933;
      --panel-2: #182244;
      --border: #273566;
      --text: #e6ecff;
      --muted: #94a3c8;
      --accent: #38bdf8;
      --green: #22c55e;
      --amber: #f59e0b;
      --red: #ef4444;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top right, #162148, var(--bg) 55%);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      padding: 1.25rem 2rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      background: rgba(11, 16, 32, 0.85);
      backdrop-filter: blur(8px);
    }
    h1 { margin: 0; font-size: 1.25rem; letter-spacing: 0.02em; }
    .subtitle { color: var(--muted); font-size: 0.875rem; }
    main { max-width: 1320px; margin: 0 auto; padding: 1.5rem; display: grid; gap: 1.25rem; grid-template-columns: 1.15fr 0.85fr; }
    @media (max-width: 980px) { main { grid-template-columns: 1fr; } }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    }
    .card h2 { margin-top: 0; font-size: 1rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.06em; }
    textarea, input, select {
      width: 100%;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.65rem 0.75rem;
      font-family: var(--mono);
      font-size: 0.82rem;
    }
    textarea { min-height: 260px; resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-top: 0.75rem; }
    .btn-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.85rem; }
    button {
      background: linear-gradient(135deg, #0284c7, #2563eb);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 0.55rem 1rem;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
    }
    button.secondary { background: var(--panel-2); border: 1px solid var(--border); color: var(--text); }
    button:hover { filter: brightness(1.1); }
    .pill {
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .pass { background: rgba(34,197,94,0.16); color: #4ade80; border: 1px solid rgba(34,197,94,0.4); }
    .fail { background: rgba(239,68,68,0.16); color: #f87171; border: 1px solid rgba(239,68,68,0.4); }
    .warn { background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }
    .neutral { background: rgba(148,163,199,0.15); color: #cbd5e1; border: 1px solid rgba(148,163,199,0.3); }
    .kv-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.65rem; margin: 0.75rem 0; }
    .metric-box { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem; }
    .metric-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; }
    .metric-val { font-size: 1rem; font-weight: 700; margin-top: 0.2rem; }
    pre {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      overflow-x: auto;
      font-family: var(--mono);
      font-size: 0.78rem;
      white-space: pre-wrap;
      word-break: break-word;
    }
    ul { margin: 0.4rem 0; padding-left: 1.2rem; }
    .small { font-size: 0.8rem; color: var(--muted); }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1</h1>
      <div class="subtitle">SPF (RFC 7208) · DKIM (RFC 6376) · DMARC (RFC 7489) · Header Forensics</div>
    </div>
    <div id="dmarcStatusBadge" class="pill neutral">Loading policy...</div>
  </header>

  <main>
    <section class="card">
      <h2>1. Raw Email &amp; Header Analyzer</h2>
      <div class="btn-row" id="sampleButtons"></div>
      <div style="margin-top: 0.75rem;">
        <textarea id="rawInput" placeholder="Paste raw RFC 5322 email or raw email headers here..."></textarea>
      </div>
      <div class="row">
        <div>
          <label class="small">Override Client IP (optional)</label>
          <input id="clientIp" placeholder="e.g. 198.51.100.10" />
        </div>
        <div>
          <label class="small">Override Envelope MAIL FROM (optional)</label>
          <input id="mailFrom" placeholder="e.g. notifications@securemail.example" />
        </div>
      </div>
      <div class="btn-row">
        <button onclick="analyzeHeader()">Analyze Authentication</button>
        <button class="secondary" onclick="signTestEmail()">Generate &amp; Load DKIM-Signed Email</button>
      </div>

      <div id="analysisOutput" style="margin-top: 1rem; display: none;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
          <div><strong>Security Verdict:</strong> <span id="verdictBadge" class="pill"></span></div>
          <div class="small">Risk Score: <strong id="riskScore">0</strong>/100</div>
        </div>
        <div class="kv-grid">
          <div class="metric-box">
            <div class="metric-label">SPF</div>
            <div class="metric-val" id="spfOutcome">-</div>
            <div class="small" id="spfDetail"></div>
          </div>
          <div class="metric-box">
            <div class="metric-label">DKIM</div>
            <div class="metric-val" id="dkimOutcome">-</div>
            <div class="small" id="dkimDetail"></div>
          </div>
          <div class="metric-box">
            <div class="metric-label">DMARC &amp; Alignment</div>
            <div class="metric-val" id="dmarcOutcome">-</div>
            <div class="small" id="dmarcDetail"></div>
          </div>
        </div>
        <div><strong>Findings &amp; Anomalies</strong><ul id="anomalyList"></ul></div>
        <div style="margin-top: 0.75rem;"><strong>Parsed Summary</strong><pre id="summaryPre"></pre></div>
      </div>
    </section>

    <section class="card">
      <h2>2. DNS Zone &amp; DMARC Policy Lifecycle</h2>
      <p class="small">Transition DMARC from <code>p=none</code> (Monitoring) to <code>p=quarantine</code> and <code>p=reject</code> (Enforced) after verifying SPF/DKIM alignment.</p>
      <div class="row">
        <div>
          <label class="small">DMARC Policy (<code>p=</code>)</label>
          <select id="policySelect">
            <option value="none">none (Monitoring)</option>
            <option value="quarantine">quarantine (Spam Folder)</option>
            <option value="reject">reject (Block Spoofing)</option>
          </select>
        </div>
        <div>
          <label class="small">Alignment Mode (<code>adkim / aspf</code>)</label>
          <select id="alignSelect">
            <option value="r">r (Relaxed — Org Domain)</option>
            <option value="s">s (Strict — Exact Domain)</option>
          </select>
        </div>
      </div>
      <div class="btn-row">
        <button onclick="updatePolicy()">Update DMARC DNS Record</button>
        <button class="secondary" onclick="loadDns()">Refresh DNS Zone</button>
      </div>
      <div style="margin-top: 1rem;">
        <strong>Published BIND Zone (<code>securemail.example</code>)</strong>
        <pre id="bindPre">Loading...</pre>
      </div>
    </section>
  </main>

  <script>
    function badgeClass(val) {
      if (!val) return 'neutral';
      const v = val.toLowerCase();
      if (v === 'pass' || v === 'trusted' || v === 'accept') return 'pass';
      if (v === 'fail' || v === 'reject' || v === 'malicious_or_spoofed') return 'fail';
      if (v === 'softfail' || v === 'quarantine' || v === 'suspicious') return 'warn';
      return 'neutral';
    }

    async function loadSamples() {
      const res = await fetch('/api/samples');
      const data = await res.json();
      const container = document.getElementById('sampleButtons');
      container.innerHTML = '';
      (data.samples || []).forEach(s => {
        const btn = document.createElement('button');
        btn.className = 'secondary';
        btn.textContent = 'Load: ' + s.name.replace(/_/g, ' ');
        btn.onclick = () => {
          document.getElementById('rawInput').value = s.content;
          analyzeHeader();
        };
        container.appendChild(btn);
      });
    }

    async function loadDns() {
      const res = await fetch('/api/dns');
      const data = await res.json();
      document.getElementById('bindPre').textContent = data.bind_zone || JSON.stringify(data.records, null, 2);
      const dmarcArr = (((data.records || {})['_dmarc.' + data.domain] || {})['TXT']) || [];
      const badge = document.getElementById('dmarcStatusBadge');
      const rec = dmarcArr[0] || 'No DMARC';
      badge.textContent = rec.includes('p=reject') ? 'DMARC: p=reject (Enforced)' :
                          rec.includes('p=quarantine') ? 'DMARC: p=quarantine' : 'DMARC: p=none (Monitoring)';
      badge.className = 'pill ' + (rec.includes('p=reject') ? 'pass' : rec.includes('p=quarantine') ? 'warn' : 'neutral');
    }

    async function updatePolicy() {
      const policy = document.getElementById('policySelect').value;
      const align = document.getElementById('alignSelect').value;
      await fetch('/api/dmarc/policy', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({policy, adkim: align, aspf: align, pct: 100})
      });
      await loadDns();
      if (document.getElementById('rawInput').value.trim()) {
        await analyzeHeader();
      }
    }

    async function signTestEmail() {
      const res = await fetch('/api/sign', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          sender: 'notifications@securemail.example',
          recipient: 'auditor@partner.example',
          subject: 'Live DKIM-Signed Verification Test',
          body: 'Signed dynamically using 2048-bit RSA-SHA256 in EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1.'
        })
      });
      const data = await res.json();
      document.getElementById('rawInput').value = data.signed_email;
      document.getElementById('clientIp').value = '198.51.100.10';
      document.getElementById('mailFrom').value = 'notifications@securemail.example';
      await analyzeHeader();
    }

    async function analyzeHeader() {
      const raw_email = document.getElementById('rawInput').value;
      if (!raw_email.trim()) return;
      const client_ip = document.getElementById('clientIp').value.trim() || null;
      const mail_from = document.getElementById('mailFrom').value.trim() || null;
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({raw_email, client_ip, mail_from})
      });
      const data = await res.json();
      document.getElementById('analysisOutput').style.display = 'block';

      const vb = document.getElementById('verdictBadge');
      vb.textContent = data.security_verdict;
      vb.className = 'pill ' + badgeClass(data.security_verdict);
      document.getElementById('riskScore').textContent = data.risk_score;

      const spf = data.spf_evaluation;
      document.getElementById('spfOutcome').innerHTML = `<span class="pill ${badgeClass(spf ? spf.result : 'none')}">${spf ? spf.result : 'not-checked'}</span>`;
      document.getElementById('spfDetail').textContent = spf ? spf.explanation : 'No client IP available.';

      const dkim = (data.dkim_evaluations || [])[0];
      document.getElementById('dkimOutcome').innerHTML = `<span class="pill ${badgeClass(dkim ? dkim.result : 'none')}">${dkim ? dkim.result : 'none'}</span>`;
      document.getElementById('dkimDetail').textContent = dkim ? dkim.reason : 'No DKIM signature.';

      const dmarc = data.dmarc_evaluation;
      document.getElementById('dmarcOutcome').innerHTML = `<span class="pill ${badgeClass(dmarc ? dmarc.result : 'none')}">${dmarc ? dmarc.result + ' (' + dmarc.disposition + ')' : 'not-checked'}</span>`;
      document.getElementById('dmarcDetail').textContent = dmarc ? `SPF aligned: ${dmarc.spf_aligned} | DKIM aligned: ${dmarc.dkim_aligned}` : '';

      const ul = document.getElementById('anomalyList');
      ul.innerHTML = '';
      if ((data.anomalies || []).length === 0) {
        ul.innerHTML = '<li class="small">No spoofing or integrity anomalies detected.</li>';
      } else {
        data.anomalies.forEach(a => {
          const li = document.createElement('li');
          li.textContent = a;
          ul.appendChild(li);
        });
      }
      document.getElementById('summaryPre').textContent = data.summary_text;
    }

    loadSamples();
    loadDns();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    return HTMLResponse(content=_DASHBOARD_HTML)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
