let moduleChart;
let latestModuleResults = [];

function joinLines(lines = []) {
  return lines.filter(Boolean).join('\n');
}

function bulletList(items = []) {
  if (!items.length) return '  • None';
  return items.map((item) => `  • ${item}`).join('\n');
}

function renderLegacyFileResult(data) {
  return joinLines([
    `📁 File: ${data.filename || '-'}`,
    `📦 Size: ${data.size_bytes ?? '-'} bytes`,
    `🧪 Detected Type: ${data.detected_type || '-'}`,
    `📊 Entropy: ${data.entropy_percentage || '-'}`,
    `ℹ️ Status: ${data.status || '-'}${data.message ? ` (${data.message})` : ''}`
  ]);
}

function renderUrlResult(data) {
  if (data.error) return `❌ ${data.error}`;
  return joinLines([
    `🌐 URL: ${data.url || '-'}`,
    `🧭 Hostname: ${data.hostname || '-'}`,
    `🔌 Port: ${data.port ?? 'Default'}`,
    `📈 Risk Score: ${data.risk_score ?? 0}/100`,
    `🛡 Verdict: ${data.verdict || '-'}`,
    '',
    '🔍 Findings:',
    bulletList(data.findings || []),
    '',
    `🔐 SSL: ${data.ssl?.valid ? 'Valid' : 'Not valid / unavailable'}`,
    data.ssl?.days_left !== undefined && data.ssl?.days_left !== null ? `⏳ SSL Days Left: ${data.ssl.days_left}` : '',
    data.ssl?.error ? `⚠️ SSL Note: ${data.ssl.error}` : '',
    '',
    `🗂 WHOIS Server: ${data.whois_server || 'N/A'}`,
    data.whois_error ? `⚠️ WHOIS Error: ${data.whois_error}` : '',
    data.whois_excerpt ? `📝 WHOIS Excerpt:\n${String(data.whois_excerpt).slice(0, 900)}` : ''
  ]);
}

function renderFileModuleResult(data) {
  if (data.error) return `❌ ${data.error}`;
  return joinLines([
    `📁 File: ${data.filename || '-'}`,
    `📦 Size: ${data.size_bytes ?? '-'} bytes`,
    `🧪 Signature: ${data.signature || '-'}`,
    `🧬 MD5: ${data.md5 || '-'}`,
    `🔒 SHA256: ${data.sha256 || '-'}`,
    `📊 Entropy: ${data.entropy ?? '-'}`,
    `📈 Threat Score: ${data.threat_score ?? 0}/100`,
    `🛡 Verdict: ${data.threat_verdict || '-'}`,
    '',
    '⚠️ Triggered Rules:',
    bulletList(data.rules_triggered || [])
  ]);
}

function renderIpResult(data) {
  if (data.error) return `❌ ${data.error}`;
  const osint = data.osint || {};
  const dnsRecords = data.dns_records || {};
  const resolvedRecords = dnsRecords['A/AAAA'] || [];

  return joinLines([
    `🌍 Indicator: ${data.indicator || '-'}`,
    `🧭 Resolved IP: ${data.resolved_ip || 'Not resolved'}`,
    `📈 Risk Score: ${data.risk_score ?? 0}/100`,
    '',
    '🧾 DNS Records:',
    resolvedRecords.length ? bulletList(resolvedRecords) : (dnsRecords.error ? `  • Error: ${dnsRecords.error}` : '  • None'),
    '',
    '🛰 OSINT:',
    `  • Status: ${osint.status || 'N/A'}`,
    `  • Country: ${osint.country || 'N/A'}`,
    `  • Region: ${osint.regionName || 'N/A'}`,
    `  • City: ${osint.city || 'N/A'}`,
    `  • ISP: ${osint.isp || 'N/A'}`,
    `  • Org: ${osint.org || 'N/A'}`,
    `  • ASN: ${osint.as || 'N/A'}`,
    osint.error ? `  • Error: ${osint.error}` : ''
  ]);
}

function renderEmailResult(data) {
  if (data.error) return `❌ ${data.error}`;
  return joinLines([
    `📨 From: ${data.from || '-'}`,
    `↩️ Reply-To: ${data.reply_to || '-'}`,
    `📬 Received Hops: ${data.received_hops ?? 0}`,
    `🛡 Verdict: ${data.verdict || '-'}`,
    `📈 Risk Score: ${data.risk_score ?? 0}/100`,
    '',
    `SPF: ${String(data.spf || '-').toUpperCase()}`,
    `DKIM: ${String(data.dkim || '-').toUpperCase()}`,
    `DMARC: ${String(data.dmarc || '-').toUpperCase()}`,
    '',
    '🔍 Findings:',
    bulletList(data.findings || [])
  ]);
}

async function analyzeUrl() {
  const value = document.getElementById('urlInput')?.value.trim();
  const box = document.getElementById('urlResult');
  if (!value || !box) return;
  box.textContent = 'Analyzing...';
  const res = await fetch('/api/url-analyzer', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url: value})
  });
  const data = await res.json();
  box.textContent = renderUrlResult(data);
  if (!data.error) latestModuleResults.push({module: 'URL Analyzer', score: data.risk_score || 0, summary: data.verdict});
  loadDashboard();
}

// File scanner used in original dashboard
async function scanFile() {
  const fileInput = document.getElementById('fileInput');
  const box = document.getElementById('fileResult');
  if (!fileInput || !box) return;
  if (!fileInput.files.length) {
    box.textContent = 'Please choose a file';
    return;
  }
  box.textContent = 'Scanning...';
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  const res = await fetch('/scan-file', {method: 'POST', body: formData});
  const data = await res.json();
  box.textContent = renderLegacyFileResult(data);
}

// File scanner used in dedicated module page
async function scanFileModule() {
  const fileInput = document.getElementById('moduleFileInput');
  const box = document.getElementById('moduleFileResult');
  if (!fileInput || !box) return;
  if (!fileInput.files.length) {
    box.textContent = 'Please choose a file';
    return;
  }
  box.textContent = 'Scanning...';
  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  const res = await fetch('/api/file-scanner', {method: 'POST', body: formData});
  const data = await res.json();
  box.textContent = renderFileModuleResult(data);
  if (!data.error) latestModuleResults.push({module: 'File Scanner', score: data.threat_score || 0, summary: data.threat_verdict});
  loadDashboard();
}

async function analyzePhishing() {
  const text = document.getElementById('phishText')?.value.trim();
  if (!text) return;

  const res = await fetch('/analyze-phishing', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  });
  const data = await res.json();

  const result = document.getElementById('phishResult');
  if (!result) return;
  result.style.display = 'block';
  document.getElementById('verdictOutput').textContent = data.verdict || '-';
  document.getElementById('riskScoreOutput').textContent = data.risk_score ?? '-';

  const box = document.getElementById('reasonsListBox');
  if (!box) return;
  if (!data.reasons || !data.reasons.length) {
    box.innerHTML = 'No suspicious indicators found.';
  } else {
    box.innerHTML = data.reasons.map(r => `• ${r}`).join('<br>');
  }
}

async function checkPassword() {
  const pwd = document.getElementById('passwordInput')?.value || '';
  const box = document.getElementById('passwordResult');
  if (!box) return;
  if (!pwd.trim()) {
    box.textContent = 'Please enter a password.';
    return;
  }

  box.textContent = 'Checking strength...';
  const res = await fetch('/check-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pwd})
  });
  const data = await res.json();
  box.innerHTML = `
    <div><b>Strength:</b> ${data.strength || '-'}</div>
    <div><b>Score:</b> ${data.score ?? '-'}/100</div>
    <div>${(data.feedback || []).map(i => `• ${i}`).join('<br>')}</div>
  `;
}

async function startSimulation() {
  const box = document.getElementById('simulationResult');
  if (!box) return;
  const res = await fetch('/start-simulation');
  const data = await res.json();
  box.textContent = JSON.stringify(data, null, 2);
}

async function viewAttacks() {
  const box = document.getElementById('attackResult');
  if (!box) return;
  box.textContent = 'Fetching attacks...';
  const res = await fetch('/view-attacks');
  const data = await res.json();
  box.textContent = JSON.stringify(data, null, 2);
}

async function lookupIP() {
  const indicator = document.getElementById('ipInput')?.value.trim();
  const box = document.getElementById('ipResult');
  if (!indicator || !box) return;
  box.textContent = 'Looking up...';
  const res = await fetch('/api/ip-lookup', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({indicator})
  });
  const data = await res.json();
  box.textContent = renderIpResult(data);
  if (!data.error) latestModuleResults.push({module: 'IP Lookup', score: data.risk_score || 0, summary: 'Lookup complete'});
  loadDashboard();
}

async function analyzeEmail() {
  const headers = document.getElementById('emailHeaders')?.value.trim();
  const box = document.getElementById('emailResult');
  if (!headers || !box) return;
  box.textContent = 'Analyzing headers...';
  const res = await fetch('/api/email-analyzer', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({headers})
  });
  const data = await res.json();
  box.textContent = renderEmailResult(data);
  if (!data.error) latestModuleResults.push({module: 'Email Analyzer', score: data.risk_score || 0, summary: data.verdict});
  loadDashboard();
}

async function loadDashboard() {
  const total = document.getElementById('totalScans');
  const finalThreat = document.getElementById('finalThreat');
  const recent = document.getElementById('recentScans');
  const chartEl = document.getElementById('moduleChart');

  if (!total && !finalThreat && !recent && !chartEl) return;

  const dash = await fetch('/api/dashboard-summary');
  const data = await dash.json();

  if (total) total.textContent = data.total_scans;
  if (finalThreat) finalThreat.textContent = `${data.final_threat_score}/100`;
  if (recent) recent.textContent = JSON.stringify(data.recent_scans, null, 2);

  if (chartEl && window.Chart) {
    const labels = Object.keys(data.module_counts || {});
    const values = Object.values(data.module_counts || {});
    if (moduleChart) moduleChart.destroy();
    moduleChart = new Chart(chartEl, {
      type: 'bar',
      data: {labels, datasets: [{label: 'Scans by Module', data: values, backgroundColor: '#4b8dff'}]},
      options: {responsive: true}
    });
  }
}

async function exportThreatReport() {
  const res = await fetch('/api/report', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({modules: latestModuleResults})
  });
  const report = await res.json();

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  let y = 10;
  doc.setFontSize(16);
  doc.text('Cyber Security Threat Report', 10, y);
  y += 10;
  doc.setFontSize(11);
  doc.text(`Generated: ${report.generated_at}`, 10, y); y += 8;
  doc.text(`Final Threat Score: ${report.final_threat_score}/100`, 10, y); y += 8;
  doc.text('Modules:', 10, y); y += 8;
  (report.modules || []).forEach((m) => {
    doc.text(`- ${m.module}: ${m.score} (${m.summary})`, 12, y);
    y += 7;
  });
  y += 5;
  doc.text('Recommendations:', 10, y); y += 8;
  (report.recommendations || []).forEach((r) => {
    doc.text(`- ${r}`, 12, y, {maxWidth: 180});
    y += 10;
  });
  doc.save('threat_report.pdf');
}

if (window.activePage === 'dashboard') {
  loadDashboard();
}


function initThemeToggle() {
  const themeToggle = document.getElementById('themeToggle');
  if (!themeToggle) return;

  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light-mode');
    themeToggle.innerText = '🌙';
  }

  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light-mode');
    const isLight = document.body.classList.contains('light-mode');
    themeToggle.innerText = isLight ? '🌙' : '☀️';
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
  });
}

function toggleChat() {
  const chat = document.getElementById('chat-widget');
  if (!chat) return;
  const isOpen = chat.classList.contains('open');
  if (isOpen) {
    chat.classList.remove('open');
  } else {
    chat.classList.add('open');
    setTimeout(() => {
      const input = document.getElementById('chat-text');
      if (input) input.focus();
    }, 60);
  }
}

function appendChatMessage(role, text) {
  const msgBox = document.getElementById('chat-messages');
  if (!msgBox) return;

  const bubble = document.createElement('div');
  bubble.className = `chat-msg ${role}`;
  bubble.textContent = text;
  msgBox.appendChild(bubble);
  msgBox.scrollTop = msgBox.scrollHeight;
}

async function sendChat() {
  const input = document.getElementById('chat-text');
  const msgBox = document.getElementById('chat-messages');
  if (!input || !msgBox) return;

  const text = input.value.trim();
  if (!text) return;

  appendChatMessage('user', text);
  input.value = '';

  try {
    const res = await fetch('/ask-ai', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({question: text})
    });
    const data = await res.json();
    if (!res.ok) {
      appendChatMessage('ai', data.answer || "I'm in offline mode right now.");
      return;
    }
    appendChatMessage('ai', data.answer || "I'm in offline mode right now.");
  } catch (err) {
    console.error(err);
    appendChatMessage('ai', "I'm in offline mode right now. Try questions like: What is phishing? How to stay safe from malware?");
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();

  const input = document.getElementById('chat-text');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        sendChat();
      }
    });
  }
});
