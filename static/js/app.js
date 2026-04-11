/* ─────────────────────────────────────────────
   PwnLab — app.js
   Ethical Password Cracking Lab Frontend
───────────────────────────────────────────── */

"use strict";

// ── Utilities ──────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const sections = {};
let opCount = 0;
let speedChart = null;
let bfJobId = null;
let bfPollTimer = null;

function showToast(msg, type = "info") {
  const colors = { success: "#3fb950", danger: "#f85149", info: "#58a6ff", warning: "#d29922" };
  const toast = document.createElement("div");
  toast.className = "toast show align-items-center border-0 mb-2";
  toast.style.borderLeft = `4px solid ${colors[type] || colors.info}`;
  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${msg}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>`;
  $("toast-container").appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

async function api(endpoint, body = null, method = "POST") {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== null) opts.body = JSON.stringify(body);
  const res = await fetch(endpoint, opts);
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || "API error");
  return json;
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-check"></i>';
    btn.classList.replace("btn-outline-secondary", "btn-outline-success");
    setTimeout(() => {
      btn.innerHTML = orig;
      btn.classList.replace("btn-outline-success", "btn-outline-secondary");
    }, 1200);
  });
}

function incOp() {
  opCount++;
  $("stats-badge").textContent = `${opCount} operation${opCount !== 1 ? "s" : ""}`;
}

// ── Sidebar navigation ─────────────────────────────────────────────────────

function initNav() {
  const links = document.querySelectorAll("#sidebar .nav-link");
  const sectionIds = ["setup","identifier","dictionary","rule","bruteforce",
                      "strength","securehash","generator","history",
                      "breach","stuffing","cracktime"];

  // Build section map
  sectionIds.forEach(id => {
    sections[id] = $(`section-${id}`);
  });

  links.forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      const sec = link.dataset.section;
      links.forEach(l => l.classList.remove("active"));
      link.classList.add("active");
      sectionIds.forEach(id => sections[id].classList.add("d-none"));
      sections[sec].classList.remove("d-none");
      $("topbar-title").innerHTML = link.innerHTML;

      if (sec === "history") loadHistory();
      if (sec === "breach") breachMaybeLoadDb();
    });
  });

  // Sidebar toggle
  $("sidebar-toggle").addEventListener("click", () => {
    document.body.classList.toggle("sidebar-collapsed");
  });
}

// ── Wordlist loader ────────────────────────────────────────────────────────

async function loadWordlists() {
  try {
    const { wordlists } = await api("/api/wordlists", null, "GET");
    ["dict-wordlist", "rule-wordlist"].forEach(selId => {
      const sel = $(selId);
      if (!sel) return;
      sel.innerHTML = "";
      wordlists.forEach(wl => {
        const opt = document.createElement("option");
        opt.value = wl; opt.textContent = wl;
        sel.appendChild(opt);
      });
    });
  } catch { /* silently ignore */ }
}

// ── SECTION: Setup ─────────────────────────────────────────────────────────

function initSetup() {
  // Pre-fill with sample passwords
  $("setup-passwords").value = "123456\npassword\niloveyou\nqwerty\nmonkey\nletmein\ndragon\nsunshine\nadmin\nwelcome";

  $("btn-generate-hashes").addEventListener("click", async () => {
    const passwords = $("setup-passwords").value;
    const algorithms = [...document.querySelectorAll(".setup-algo:checked")].map(cb => cb.value);

    if (!passwords.trim()) return showToast("Enter at least one password.", "warning");
    if (!algorithms.length) return showToast("Select at least one algorithm.", "warning");

    const btn = $("btn-generate-hashes");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Generating…';
    try {
      const { records } = await api("/api/generate-hashes", { passwords, algorithms });
      const tbody = $("setup-table").querySelector("tbody");
      tbody.innerHTML = "";
      records.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td class="text-warning">${escHtml(r.plaintext)}</td>
                        <td><span class="badge bg-secondary">${escHtml(r.algorithm)}</span></td>
                        <td class="text-success" style="font-family:monospace;font-size:11px">${escHtml(r.hash)}</td>`;
        tbody.appendChild(tr);
      });
      $("setup-result").classList.remove("d-none");
      showToast(`Generated ${records.length} hashes. Saved to setup/hashes.txt`, "success");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-gear"></i> Generate Hashes';
    }
  });
}

// ── SECTION: Hash Identifier ───────────────────────────────────────────────

function initIdentifier() {
  $("btn-identify").addEventListener("click", async () => {
    const hashes = $("identify-hashes").value;
    if (!hashes.trim()) return showToast("Paste at least one hash.", "warning");

    const btn = $("btn-identify");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyzing…';
    try {
      const { results } = await api("/api/identify-hash", { hashes });
      const tbody = $("identify-tbody");
      tbody.innerHTML = "";
      results.forEach(r => {
        const tr = document.createElement("tr");
        const guesses = r.identified.join(", ");
        tr.innerHTML = `<td style="font-family:monospace;font-size:11px">${escHtml(r.hash.slice(0,24))}${r.hash.length>24?"…":""}</td>
                        <td><span class="badge bg-secondary">${escHtml(r.declared)}</span></td>
                        <td class="text-info">${escHtml(guesses)}</td>`;
        tbody.appendChild(tr);
      });
      $("identify-result").classList.remove("d-none");
      showToast(`Analyzed ${results.length} hash(es).`, "info");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-search"></i> Identify Hashes';
    }
  });
}

// ── SECTION: Dictionary Attack ─────────────────────────────────────────────

function initDictionary() {
  $("btn-dict-attack").addEventListener("click", async () => {
    const hashes    = $("dict-hashes").value;
    const wordlist  = $("dict-wordlist").value;
    const algorithm = $("dict-algo").value;

    if (!hashes.trim()) return showToast("Enter at least one hash.", "warning");

    const btn = $("btn-dict-attack");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Attacking…';
    try {
      const data = await api("/api/dictionary-attack", { hashes, wordlist, algorithm });
      const tbody = $("dict-tbody");
      tbody.innerHTML = "";
      data.results.forEach(r => {
        const cls = r.cracked ? "badge-cracked" : "badge-notfound";
        const ico = r.cracked ? "fa-lock-open" : "fa-lock";
        tbody.innerHTML += `<tr>
          <td style="font-family:monospace;font-size:11px">${escHtml(r.hash)}</td>
          <td><span class="badge bg-secondary">${escHtml(r.algorithm)}</span></td>
          <td class="${cls}"><i class="fa-solid ${ico}"></i> ${r.cracked ? "CRACKED" : "NOT FOUND"}</td>
          <td class="${r.cracked ? "text-warning fw-bold" : "text-muted"}">${escHtml(r.plaintext)}</td>
          <td class="text-muted">${r.attempts.toLocaleString()}</td>
        </tr>`;
      });

      const statsDiv = $("dict-stats");
      statsDiv.innerHTML = `
        <span class="stat-chip"><i class="fa-solid fa-bullseye text-danger"></i> Cracked: <span class="val text-success">${data.cracked}/${data.total}</span></span>
        <span class="stat-chip"><i class="fa-solid fa-clock"></i> Time: <span class="val">${data.elapsed}s</span></span>
        <span class="stat-chip"><i class="fa-solid fa-gauge"></i> Rate: <span class="val">${data.rate.toLocaleString()} h/s</span></span>
        <span class="stat-chip"><i class="fa-solid fa-list"></i> Wordlist: <span class="val">${data.wordlist_size.toLocaleString()} words</span></span>`;

      $("dict-result").classList.remove("d-none");
      showToast(`${data.cracked}/${data.total} hashes cracked in ${data.elapsed}s`, data.cracked > 0 ? "success" : "warning");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Dictionary Attack';
    }
  });
}

// ── SECTION: Rule-Based Attack ─────────────────────────────────────────────

function initRuleAttack() {
  $("btn-rule-attack").addEventListener("click", async () => {
    const hash      = $("rule-hash").value.trim();
    const algorithm = $("rule-algo").value;
    const wordlist  = $("rule-wordlist").value;
    const rules     = [...document.querySelectorAll(".rule-cb:checked")].map(cb => cb.value);

    if (!hash) return showToast("Enter a target hash.", "warning");
    if (!rules.length) return showToast("Select at least one rule.", "warning");

    const btn = $("btn-rule-attack");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Attacking…';
    try {
      const r = await api("/api/rule-attack", { hash, algorithm, wordlist, rules });
      const box = $("rule-result-box");
      if (r.cracked) {
        box.innerHTML = `<div class="rule-cracked">
          <div class="fw-bold text-success fs-5"><i class="fa-solid fa-lock-open"></i> CRACKED</div>
          <div class="mt-2"><span class="text-muted">Password:</span> <code class="text-warning fs-5">${escHtml(r.plaintext)}</code></div>
          <div class="mt-1 text-muted"><span>Rule applied:</span> <code>${escHtml(r.rule_hint)}</code></div>
          <div class="d-flex gap-3 mt-2 flex-wrap">
            <span class="stat-chip"><i class="fa-solid fa-list-ol"></i> Attempts: <span class="val">${r.attempts.toLocaleString()}</span></span>
            <span class="stat-chip"><i class="fa-solid fa-clock"></i> Time: <span class="val">${r.elapsed}s</span></span>
            <span class="stat-chip"><i class="fa-solid fa-gauge"></i> Rate: <span class="val">${r.rate.toLocaleString()} h/s</span></span>
          </div>
        </div>`;
        showToast(`Rule attack cracked: '${r.plaintext}'`, "success");
      } else {
        box.innerHTML = `<div class="rule-notfound">
          <div class="fw-bold text-danger"><i class="fa-solid fa-times"></i> NOT FOUND</div>
          <div class="mt-1 text-muted">${r.attempts.toLocaleString()} candidates tried in ${r.elapsed}s</div>
          <div class="mt-1 text-muted small">Try adding more rules, a larger wordlist, or switch to brute force.</div>
        </div>`;
        showToast("Hash not found with selected rules.", "warning");
      }
      $("rule-result").classList.remove("d-none");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Rule-Based Attack';
    }
  });
}

// ── SECTION: Brute Force ───────────────────────────────────────────────────

function searchSpace(charset, maxLen) {
  const sizes = { digits: 10, lowercase: 26, uppercase: 26, alpha: 52, alphanum: 62, common: 95 };
  const n = sizes[charset] || 10;
  let total = 0;
  for (let l = 1; l <= maxLen; l++) total += Math.pow(n, l);
  return total;
}

function updateSearchSpaceLabel() {
  const cs = $("bf-charset").value;
  const ml = parseInt($("bf-maxlen").value) || 4;
  const total = searchSpace(cs, ml);
  $("bf-search-space").textContent = `Search space: ${total.toLocaleString()} combinations`;
}

function initBruteForce() {
  $("bf-charset").addEventListener("change", updateSearchSpaceLabel);
  $("bf-maxlen").addEventListener("input", updateSearchSpaceLabel);
  updateSearchSpaceLabel();

  $("btn-bf-start").addEventListener("click", async () => {
    // Cancel any in-progress job
    if (bfJobId && bfPollTimer) {
      clearInterval(bfPollTimer);
      await fetch(`/api/brute-force/cancel/${bfJobId}`, { method: "POST" });
      bfJobId = null;
    }

    const hash      = $("bf-hash").value.trim();
    const algorithm = $("bf-algo").value;
    const charset   = $("bf-charset").value;
    const max_length = parseInt($("bf-maxlen").value) || 4;

    if (!hash) return showToast("Enter a target hash.", "warning");

    const btn = $("btn-bf-start");
    btn.disabled = true;
    $("btn-bf-cancel").classList.remove("d-none");

    $("bf-progress-area").classList.remove("d-none");
    $("bf-result-box").innerHTML = "";
    $("bf-progress-bar").style.width = "0%";
    $("bf-pct").textContent = "0%";
    $("bf-status-text").textContent = "Starting…";
    $("bf-live-stats").innerHTML = "";

    try {
      const { job_id, total } = await api("/api/brute-force/start", { hash, algorithm, charset, max_length });
      bfJobId = job_id;

      bfPollTimer = setInterval(async () => {
        try {
          const job = await api(`/api/brute-force/status/${bfJobId}`, null, "GET");
          const pct = Math.min(job.progress || 0, 100);

          $("bf-progress-bar").style.width = pct + "%";
          $("bf-pct").textContent = pct.toFixed(1) + "%";
          $("bf-live-stats").innerHTML = `
            <span class="stat-chip"><i class="fa-solid fa-list-ol"></i> Attempts: <span class="val">${(job.attempts||0).toLocaleString()}</span></span>
            <span class="stat-chip"><i class="fa-solid fa-gauge"></i> Rate: <span class="val">${(job.rate||0).toLocaleString()} h/s</span></span>
            <span class="stat-chip"><i class="fa-solid fa-clock"></i> Elapsed: <span class="val">${job.elapsed||0}s</span></span>`;

          if (job.status === "cracked") {
            clearInterval(bfPollTimer); bfPollTimer = null;
            $("bf-status-text").textContent = "CRACKED!";
            $("bf-progress-bar").classList.remove("bg-danger");
            $("bf-progress-bar").classList.add("bg-success");
            $("bf-progress-bar").classList.remove("progress-bar-animated");
            $("bf-result-box").innerHTML = `<div class="bf-cracked mt-2">
              <div class="fw-bold text-success fs-5"><i class="fa-solid fa-lock-open"></i> CRACKED</div>
              <div class="mt-2"><span class="text-muted">Password:</span> <code class="text-warning fs-5">${escHtml(job.plaintext)}</code></div>
              <div class="d-flex gap-3 mt-2 flex-wrap">
                <span class="stat-chip">Attempts: <span class="val">${job.attempts.toLocaleString()}</span></span>
                <span class="stat-chip">Time: <span class="val">${job.elapsed}s</span></span>
                <span class="stat-chip">Rate: <span class="val">${job.rate.toLocaleString()} h/s</span></span>
              </div>
            </div>`;
            showToast(`Brute force cracked: '${job.plaintext}'`, "success");
            resetBfButtons(btn);
            incOp();
          } else if (job.status === "not_found") {
            clearInterval(bfPollTimer); bfPollTimer = null;
            $("bf-status-text").textContent = "NOT FOUND";
            $("bf-progress-bar").classList.remove("progress-bar-animated");
            $("bf-result-box").innerHTML = `<div class="bf-notfound mt-2">
              <div class="fw-bold text-danger"><i class="fa-solid fa-times"></i> NOT FOUND in search space</div>
              <div class="mt-1 text-muted">${job.attempts.toLocaleString()} attempts in ${job.elapsed}s — password exceeds max length or charset.</div>
            </div>`;
            showToast("Not found. Try increasing max length or charset.", "warning");
            resetBfButtons(btn);
            incOp();
          } else if (job.status === "cancelled") {
            clearInterval(bfPollTimer); bfPollTimer = null;
            $("bf-status-text").textContent = "Cancelled";
            $("bf-progress-bar").classList.remove("progress-bar-animated");
            resetBfButtons(btn);
          }
        } catch { clearInterval(bfPollTimer); bfPollTimer = null; resetBfButtons(btn); }
      }, 500);

    } catch (err) {
      showToast(err.message, "danger");
      resetBfButtons(btn);
    }
  });

  $("btn-bf-cancel").addEventListener("click", async () => {
    if (bfJobId) {
      clearInterval(bfPollTimer); bfPollTimer = null;
      await fetch(`/api/brute-force/cancel/${bfJobId}`, { method: "POST" });
      bfJobId = null;
      $("bf-status-text").textContent = "Cancelled by user";
      $("bf-progress-bar").classList.remove("progress-bar-animated");
      resetBfButtons($("btn-bf-start"));
    }
  });
}

function resetBfButtons(btn) {
  btn.disabled = false;
  $("btn-bf-cancel").classList.add("d-none");
}

// ── SECTION: Strength Checker ──────────────────────────────────────────────

function initStrength() {
  $("btn-show-pw").addEventListener("click", () => {
    const inp = $("strength-input");
    const ico = $("btn-show-pw").querySelector("i");
    if (inp.type === "password") {
      inp.type = "text";
      ico.className = "fa-solid fa-eye-slash";
    } else {
      inp.type = "password";
      ico.className = "fa-solid fa-eye";
    }
  });

  $("strength-input").addEventListener("keydown", e => {
    if (e.key === "Enter") $("btn-strength-check").click();
  });

  $("btn-strength-check").addEventListener("click", async () => {
    const password = $("strength-input").value;
    if (!password) return showToast("Enter a password to analyze.", "warning");

    const btn = $("btn-strength-check");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyzing…';
    try {
      const data = await api("/api/strength-check", { password });

      // Score circle
      const circle = $("score-circle");
      circle.textContent = data.total;
      let col = "#f85149";
      if (data.total >= 70) col = "#3fb950";
      else if (data.total >= 50) col = "#d29922";
      else if (data.total >= 30) col = "#fb8f44";
      circle.style.borderColor = col;
      circle.style.color = col;

      $("score-label-text").textContent = data.label;
      $("score-label-text").style.color = col;
      $("score-entropy-text").textContent = `Entropy: ${data.entropy} bits ${data.entropy >= 60 ? "✓" : "⚠ (target ≥ 60)"}`;

      // Progress bar
      const bar = $("score-bar");
      bar.style.width = data.total + "%";
      bar.style.backgroundColor = col;

      // Check items
      const checksDiv = $("strength-checks");
      checksDiv.innerHTML = "";
      data.checks.forEach(c => {
        const cls = c.score > 0 ? "ci-pos" : c.score < 0 ? "ci-neg" : "ci-neu";
        const sign = c.score >= 0 ? "+" : "";
        checksDiv.innerHTML += `<div class="check-item">
          <span class="ci-score ${cls}">${sign}${c.score}</span>
          <span>${escHtml(c.msg)}</span>
        </div>`;
      });

      $("strength-result").classList.remove("d-none");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> Analyze Strength';
    }
  });
}

// ── SECTION: Secure Hashing ────────────────────────────────────────────────

const VERDICTS = { Terrible: "terrible", Poor: "poor", Good: "good", Best: "best" };

function initSecureHash() {
  $("btn-secure-hash").addEventListener("click", async () => {
    const password = $("secure-pw").value;
    if (!password) return showToast("Enter a password.", "warning");

    const btn = $("btn-secure-hash");
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Hashing…';
    $("secure-result").classList.add("d-none");
    $("secure-spinner").classList.remove("d-none");

    try {
      const data = await api("/api/secure-hash", { password });
      renderSecureHashResults(data.results);
      showToast("Algorithm comparison complete.", "success");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Comparison';
      $("secure-spinner").classList.add("d-none");
    }
  });
}

function renderSecureHashResults(results) {
  const cards = $("secure-cards");
  cards.innerHTML = "";

  results.forEach(r => {
    const vc = VERDICTS[r.verdict] || "good";
    const col = $("section-securehash"); // needed for card
    cards.innerHTML += `<div class="col-md-3">
      <div class="hash-card">
        <div class="algo-name">${escHtml(r.algorithm)}</div>
        <div class="hash-val">${escHtml(r.hash.slice(0, 60))}…</div>
        <div class="time-val verdict-${vc}">${r.time_ms < 1 ? r.time_ms.toFixed(3) : r.time_ms.toFixed(0)} ms</div>
        <div class="mt-1">
          ${r.salted ? '<span class="badge bg-success me-1">Salted</span>' : '<span class="badge bg-danger me-1">No salt</span>'}
          ${r.memory_hard ? '<span class="badge bg-primary">Memory-hard</span>' : ''}
        </div>
        <div class="verdict verdict-${vc} mt-1">${escHtml(r.verdict)}</div>
        <div class="mt-1 text-muted" style="font-size:11px">GPU: ${escHtml(r.gpu_rate)}</div>
      </div>
    </div>`;
  });

  // Chart
  if (speedChart) { speedChart.destroy(); speedChart = null; }
  const ctx = $("hash-speed-chart").getContext("2d");
  const labels = results.map(r => r.algorithm);
  const times  = results.map(r => r.time_ms);
  const bgs    = ["#f85149aa", "#fb8f44aa", "#d29922aa", "#3fb950aa"];

  speedChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Hash time (ms)",
        data: times,
        backgroundColor: bgs,
        borderColor: bgs.map(c => c.replace("aa", "ff")),
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        title: { display: true, text: "Hash Computation Time (ms) — lower is faster, but slower = more secure for passwords", color: "#8b949e", font: { size: 12 } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.raw.toLocaleString()} ms` } }
      },
      scales: {
        x: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
        y: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" }, beginAtZero: true,
             title: { display: true, text: "ms", color: "#8b949e" } }
      }
    }
  });

  $("secure-result").classList.remove("d-none");
}

// ── SECTION: Password Generator ────────────────────────────────────────────

function initGenerator() {
  document.querySelectorAll("input[name='gen-mode']").forEach(radio => {
    radio.addEventListener("change", () => {
      const isPw = $("gen-mode-pw").checked;
      $("gen-pw-opts").classList.toggle("d-none", !isPw);
      $("gen-pp-opts").classList.toggle("d-none", isPw);
    });
  });

  $("btn-generate").addEventListener("click", async () => {
    const mode = $("gen-mode-pw").checked ? "password" : "passphrase";
    const count = parseInt($("gen-count").value) || 8;

    const body = { mode, count };
    if (mode === "password") {
      body.length  = parseInt($("gen-length").value);
      body.use_upper   = $("gen-upper").checked;
      body.use_digits  = $("gen-digits").checked;
      body.use_symbols = $("gen-symbols").checked;
      body.exclude_ambiguous = $("gen-noamb").checked;
    } else {
      body.words     = parseInt($("gen-words").value);
      body.separator = $("gen-separator").value || "-";
    }

    const btn = $("btn-generate");
    btn.disabled = true;
    try {
      const { results } = await api("/api/generate-password", body);
      const container = $("gen-result");
      container.innerHTML = "";
      results.forEach(r => {
        const row = document.createElement("div");
        row.className = "gen-row";
        row.innerHTML = `
          <span class="pw-text">${escHtml(r.password)}</span>
          <span class="pw-meta">${r.entropy} bits · ${r.strength}</span>
          <button class="btn btn-sm btn-outline-secondary btn-copy">
            <i class="fa-regular fa-copy"></i>
          </button>`;
        row.querySelector(".btn-copy").addEventListener("click", function() {
          copyToClipboard(r.password, this);
        });
        container.appendChild(row);
      });
      showToast(`${results.length} password(s) generated.`, "success");
      incOp();
    } catch (err) {
      showToast(err.message, "danger");
    } finally {
      btn.disabled = false;
    }
  });

  // Auto-generate on load
  $("btn-generate").click();
}

// ── SECTION: History ───────────────────────────────────────────────────────

async function loadHistory() {
  try {
    const { history } = await api("/api/history", null, "GET");
    const tbody   = $("history-tbody");
    const empty   = $("history-empty");
    const table   = $("history-table");

    if (!history.length) {
      empty.classList.remove("d-none");
      table.classList.add("d-none");
      return;
    }

    empty.classList.add("d-none");
    table.classList.remove("d-none");
    tbody.innerHTML = "";

    const statusClass = { done: "text-success", cracked: "text-success", not_found: "text-warning", started: "text-info", cancelled: "text-secondary" };

    history.forEach(h => {
      const cls = statusClass[h.status] || "text-muted";
      tbody.innerHTML += `<tr>
        <td>${escHtml(h.timestamp)}</td>
        <td><span class="badge bg-secondary">${escHtml(h.operation)}</span></td>
        <td class="text-muted">${escHtml(h.details || "")}</td>
        <td class="${cls} fw-bold">${escHtml(h.status || "")}</td>
      </tr>`;
    });
  } catch { /* silent */ }
}

function initHistory() {
  $("btn-refresh-history").addEventListener("click", loadHistory);
  $("btn-clear-history").addEventListener("click", async () => {
    await api("/api/history/clear");
    opCount = 0;
    $("stats-badge").textContent = "0 operations";
    loadHistory();
    showToast("History cleared.", "info");
  });
}

// ── Boot ───────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initNav();
  loadWordlists();
  initSetup();
  initIdentifier();
  initDictionary();
  initRuleAttack();
  initBruteForce();
  initStrength();
  initSecureHash();
  initGenerator();
  initHistory();
  initBreach();
  initStuffing();
  initCrackTime();
});

// ════════════════════════════════════════════════════════════
//  REAL-LIFE SIMULATIONS
// ════════════════════════════════════════════════════════════

let crackedEmployees = [];   // populated after breach simulation
let breachDbLoaded   = false;
let crackTimeChart   = null;

// ── BREACH SIMULATION ────────────────────────────────────────

function initBreach() {
  $("btn-load-db").addEventListener("click", () => loadBreachDb(true));
  $("btn-run-breach").addEventListener("click", runBreachSim);
}

async function breachMaybeLoadDb() {
  if (!breachDbLoaded) await loadBreachDb(false);
}

async function loadBreachDb(showToastMsg) {
  try {
    const data = await api("/api/breach/database", null, "GET");
    const tbody = $("breach-db-tbody");
    tbody.innerHTML = "";
    data.employees.forEach(emp => {
      const clLower = emp.clearance.toLowerCase();
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${emp.id}</td>
        <td>${emp.name}</td>
        <td>${emp.role}</td>
        <td><small>${emp.email}</small></td>
        <td><span class="badge bg-secondary">${emp.hash_algo.toUpperCase()}</span></td>
        <td><span class="clearance-badge cl-${clLower}">${emp.clearance}</span></td>
        <td><small>${emp.systems.join(", ")}</small></td>
      `;
      tbody.appendChild(tr);
    });
    $("breach-db-table-wrap").classList.remove("d-none");
    breachDbLoaded = true;
    if (showToastMsg) showToast("Database loaded.", "success");
  } catch(e) { showToast("Failed to load database: " + e.message, "danger"); }
}

async function runBreachSim() {
  const btn = $("btn-run-breach");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Running...';
  $("breach-timeline").classList.add("d-none");
  $("breach-summary").classList.add("d-none");
  try {
    const data = await api("/api/breach/simulate");
    crackedEmployees = data.cracked_employees || [];
    renderBreachTimeline(data);
    renderBreachSummary(data);
    // Unlock stuffing section
    if (crackedEmployees.length > 0) {
      $("btn-run-stuffing").textContent = "";
      $("btn-run-stuffing").innerHTML = '<i class="fa-solid fa-play"></i> Run Credential Stuffing';
      $("btn-run-stuffing").disabled = false;
      $("stuffing-prereq").textContent = `${crackedEmployees.length} cracked credential(s) ready.`;
    }
  } catch(e) { showToast("Breach simulation error: " + e.message, "danger"); }
  btn.disabled = false;
  btn.innerHTML = '<i class="fa-solid fa-rotate-right"></i> Re-run Breach Attack';
}

function renderBreachTimeline(data) {
  const wrap = $("breach-timeline");
  wrap.innerHTML = "";
  wrap.classList.remove("d-none");

  const waves = [
    { key: "wave1", label: "Wave 1 — Dictionary Attack", color: "wave-red"    },
    { key: "wave2", label: "Wave 2 — Rule-Based Attack",  color: "wave-yellow" },
    { key: "wave3", label: "Wave 3 — Brute-Force Attack", color: "wave-purple" },
  ];

  waves.forEach(w => {
    const events = data.events[w.key] || [];
    const block = document.createElement("div");
    block.className = "wave-block";
    block.innerHTML = `<div class="wave-title ${w.color}">${w.label} — ${events.filter(e=>e.status==="cracked").length} cracked</div>`;
    const tlWrap = document.createElement("div");
    tlWrap.className = "timeline-wrap";
    events.forEach(ev => {
      const d = document.createElement("div");
      const cls = ev.status === "cracked" ? "ev-cracked" : ev.status === "survived" ? "ev-survived" : "ev-info";
      d.className = `tl-event ${cls}`;
      const badge = ev.status === "cracked" ? "cracked" : ev.status === "survived" ? "survived" : "skipped";
      const icon  = ev.status === "cracked" ? "🔓" : ev.status === "survived" ? "🛡️" : "ℹ️";
      d.innerHTML = `<span class="ev-badge ${badge}">${ev.status}</span>${icon} <strong>${ev.name || ""}</strong> ${ev.message || ""}`;
      tlWrap.appendChild(d);
    });
    block.appendChild(tlWrap);
    wrap.appendChild(block);
  });
}

function renderBreachSummary(data) {
  // Stat cards
  const cards = $("breach-summary-cards");
  cards.innerHTML = "";
  const stats = [
    { label: "Accounts Cracked",  val: data.total_cracked,   cls: "text-danger" },
    { label: "Accounts Safe",     val: data.total_survived,  cls: "text-success" },
    { label: "Wave 1 Victims",    val: (data.events.wave1||[]).filter(e=>e.status==="cracked").length, cls: "text-warning" },
    { label: "Wave 2 Victims",    val: (data.events.wave2||[]).filter(e=>e.status==="cracked").length, cls: "text-warning" },
    { label: "Wave 3 Victims",    val: (data.events.wave3||[]).filter(e=>e.status==="cracked").length, cls: "text-warning" },
    { label: "Survivors",         val: (data.survivors||[]).length, cls: "text-success" },
  ];
  stats.forEach(s => {
    const col = document.createElement("div");
    col.className = "col-6 col-md-4 col-lg-2";
    col.innerHTML = `<div class="blast-card text-center"><div class="${s.cls}" style="font-size:2rem;font-weight:700">${s.val}</div><div class="text-muted small">${s.label}</div></div>`;
    cards.appendChild(col);
  });

  // Blast radius
  const br = $("breach-blast-radius");
  let html = '<strong><i class="fa-solid fa-radiation text-danger"></i> Blast Radius Analysis</strong><div class="row g-2 mt-2">';
  (data.cracked_employees || []).forEach(emp => {
    html += `<div class="col-md-4">
      <div class="blast-card cracked">
        <div class="d-flex justify-content-between align-items-center">
          <strong>${emp.name}</strong>
          <span class="clearance-badge cl-${emp.clearance.toLowerCase()}">${emp.clearance}</span>
        </div>
        <div class="text-muted small">${emp.role}</div>
        <div class="text-danger small mt-1">Password: <code>${emp.plaintext}</code></div>
        <div class="text-muted small mt-1"><i class="fa-solid fa-server"></i> ${emp.systems.join(", ")}</div>
      </div>
    </div>`;
  });
  (data.survivors || []).forEach(emp => {
    html += `<div class="col-md-4">
      <div class="blast-card safe">
        <div class="d-flex justify-content-between align-items-center">
          <strong>${emp.name}</strong>
          <span class="clearance-badge cl-${emp.clearance.toLowerCase()}">${emp.clearance}</span>
        </div>
        <div class="text-muted small">${emp.role}</div>
        <div class="text-success small mt-1"><i class="fa-solid fa-shield-halved"></i> Password resisted all attacks</div>
      </div>
    </div>`;
  });
  html += '</div>';
  br.innerHTML = html;

  $("breach-summary").classList.remove("d-none");
}

// ── CREDENTIAL STUFFING ──────────────────────────────────────

function initStuffing() {
  const btn = $("btn-run-stuffing");
  btn.disabled = true;
  btn.addEventListener("click", runCredentialStuffing);
}

async function runCredentialStuffing() {
  if (crackedEmployees.length === 0) {
    showToast("Run the Breach Simulation first!", "warning");  return;
  }
  const btn = $("btn-run-stuffing");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Stuffing...';
  try {
    const data = await api("/api/credential-stuffing", { cracked_employees: crackedEmployees });
    renderStuffingGrid(data);
  } catch(e) { showToast("Stuffing error: " + e.message, "danger"); }
  btn.disabled = false;
  btn.innerHTML = '<i class="fa-solid fa-arrows-spin"></i> Re-run Credential Stuffing';
}

function renderStuffingGrid(data) {
  const wrap = $("stuffing-result");
  wrap.innerHTML = "";
  wrap.classList.remove("d-none");

  const services = data.services;
  const results  = data.results;   // { emp_id: { service: bool } }
  const employees = crackedEmployees;

  // Summary stat
  let totalHits = 0;
  Object.values(results).forEach(svcMap => { Object.values(svcMap).forEach(v => { if(v) totalHits++; }); });
  wrap.innerHTML = `
    <div class="alert alert-danger mb-3">
      <strong><i class="fa-solid fa-triangle-exclamation"></i> ${totalHits} successful logins</strong>
      across ${services.length} services using just the MegaBank XYZ leaked passwords.
    </div>`;

  // Grid table
  let tbl = `<div class="stuffing-grid"><table class="table table-sm result-table table-bordered">`;
  // Header row: service names
  tbl += "<thead><tr><th>Employee</th>";
  services.forEach(svc => { tbl += `<th class="svc-col">${svc}</th>`; });
  tbl += "<th>Hit rate</th></tr></thead><tbody>";

  employees.forEach(emp => {
    const svcMap = results[emp.id] || {};
    let hits = 0;
    services.forEach(s => { if (svcMap[s]) hits++; });
    tbl += `<tr><td><strong>${emp.name}</strong><br><small class="text-muted">${emp.role}</small></td>`;
    services.forEach(svc => {
      tbl += svcMap[svc]
        ? `<td class="stuff-hit"><i class="fa-solid fa-check"></i></td>`
        : `<td class="stuff-miss">✗</td>`;
    });
    const pct = Math.round(hits / services.length * 100);
    tbl += `<td class="text-center"><span class="${pct>50?'text-danger':'text-warning'}">${hits}/${services.length}</span></td></tr>`;
  });

  tbl += "</tbody></table></div>";
  wrap.insertAdjacentHTML("beforeend", tbl);

  wrap.insertAdjacentHTML("beforeend", `
    <div class="lesson-box mt-3">
      <strong><i class="fa-solid fa-graduation-cap"></i> Takeaway</strong><br>
      An attacker cracked <strong>${employees.length} MegaBank XYZ accounts</strong> and immediately
      gained access to <strong>${totalHits} additional logins</strong> on external services — 
      all because employees reused passwords. A password manager eliminates this entirely.
    </div>`);
}

// ── CRACK-TIME CALCULATOR ─────────────────────────────────────

function initCrackTime() {
  $("btn-calc-crack").addEventListener("click", calcCrackTime);
  // Also update combo display on slider / select changes
  ["ct-length", "ct-charset"].forEach(id => {
    $(id).addEventListener("input", updateComboDisplay);
    $(id).addEventListener("change", updateComboDisplay);
  });
  updateComboDisplay();
}

const CHARSET_SIZES = { digits: 10, lowercase: 26, alpha: 52, alphanum: 62, full: 95 };

function updateComboDisplay() {
  const len  = parseInt($("ct-length").value);
  const csz  = CHARSET_SIZES[$("ct-charset").value] || 62;
  const combos = Math.pow(csz, len);
  $("ct-combo-val").textContent  = combos.toExponential(3);
  $("ct-combo-sub").textContent  = `= ${csz}^${len} combinations`;
}

async function calcCrackTime() {
  const payload = {
    length:  parseInt($("ct-length").value),
    charset: $("ct-charset").value,
    algo:    $("ct-algo").value,
  };
  try {
    const data = await api("/api/crack-time", payload);
    renderCrackTimeResult(data);
  } catch(e) { showToast("Crack-time error: " + e.message, "danger"); }
}

function renderCrackTimeResult(data) {
  const cardsWrap = $("ct-attacker-cards");
  cardsWrap.innerHTML = "";

  const ICONS = { laptop_cpu: "💻", gaming_gpu: "🎮", gpu_cluster: "🖥️", nation_state: "🌐" };

  data.profiles.forEach(p => {
    const badge = feasibilityBadge(p.feasibility);
    const col = document.createElement("div");
    col.className = "col-6 col-md-3";
    col.innerHTML = `
      <div class="attacker-card h-100">
        <div class="fs-4">${ICONS[p.id] || "⚡"}</div>
        <div class="attacker-name">${p.name}</div>
        <div class="hps-label">${p.hps_label} hashes/sec</div>
        <div class="crack-time-value">${p.avg_time}</div>
        <div class="text-muted small mb-2">worst case: ${p.worst_time}</div>
        <span class="feasibility-badge ${badge.cls}">${badge.label}</span>
      </div>`;
    cardsWrap.appendChild(col);
  });

  // Bar chart
  const labels = data.profiles.map(p => p.name);
  const vals   = data.profiles.map(p => Math.log10(Math.max(p.avg_seconds, 1)));
  if (crackTimeChart) crackTimeChart.destroy();
  crackTimeChart = new Chart($("crack-time-chart"), {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "log₁₀(seconds)", data: vals,
        backgroundColor: ["#f85149","#fb8f44","#d29922","#58a6ff"],
        borderWidth: 0, borderRadius: 4 }]
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: "#8b949e" } } },
      scales: {
        x: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" } },
        y: { ticks: { color: "#8b949e" }, grid: { color: "#21262d" },
             title: { display: true, text: "log₁₀(seconds)", color: "#8b949e" } }
      }
    }
  });

  // Lesson
  const algoName = data.algo.toUpperCase();
  const best = data.profiles.reduce((a,b) => a.avg_seconds < b.avg_seconds ? a : b);
  $("ct-lesson").innerHTML = `
    <strong><i class="fa-solid fa-graduation-cap"></i> What This Tells You</strong><br>
    With <strong>${algoName}</strong>, a ${data.length}-char ${$("ct-charset").value} password takes
    as little as <strong>${best.avg_time}</strong> to crack on a <em>${best.name}</em>.
    ${data.algo === "md5" || data.algo === "sha1" || data.algo === "sha256"
      ? "<span class='text-danger'>This algorithm is designed for speed — terrible for passwords.</span> Use <strong>bcrypt</strong> or <strong>Argon2id</strong> instead."
      : "<span class='text-success'>Great choice of algorithm!</span> Slow hashing dramatically raises attacker cost."
    }`;

  $("ct-empty").classList.add("d-none");
  $("ct-result").classList.remove("d-none");
}

function feasibilityBadge(f) {
  const map = {
    trivial:    { cls: "badge-trivial",    label: "Trivial"    },
    easy:       { cls: "badge-easy",       label: "Easy"       },
    moderate:   { cls: "badge-moderate",   label: "Moderate"   },
    hard:       { cls: "badge-hard",       label: "Hard"       },
    infeasible: { cls: "badge-infeasible", label: "Infeasible" },
  };
  return map[f] || map["moderate"];
}
