"use strict";
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const viewNames = {pool: "邮箱管理", launch: "注册工作台", jobs: "任务队列", results: "任务结果", settings: "运行配置"};
let accounts = [];
let passwordRequest = 0;
let batchLoading = false;
let activeBatchId = "";
let balanceLoading = false;
let balanceCheckedAt = 0;
let activeView = "pool";
let resumeJobId = "";
const MAX_BATCH_ACCOUNTS = 100;
const MAX_BATCH_PROXIES = 100;
const MAX_BATCH_WORKERS = 32;
const stateLabels = {spare: "备用", registered: "已注册", reserved: "运行中", human_required: "需要人工", code_required: "等待验证码", needs_check: "需核对",
  rate_limited: "限流冷却", partial: "部分完成", running: "运行中", queued: "等待启动",
  completed: "已确认完成", success: "已确认完成", failed: "失败", cancelled: "已取消", interrupted: "已中断"};
const integrationLabels = {disabled: "未启用导入", ready: "已导入并检测通过", imported: "已导入未确认可用",
  check_failed: "已导入，检测失败", failed: "导入失败", unknown: "导入结果需核对", rejected: "导入被拒绝", sending: "正在导入"};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"}[char]));
}

function resultPresentation(state, result = {}) {
  const reasons = {
    ERROR_CAPTCHA_UNSOLVABLE: ["求解服务失败", "服务未能完成本次求解，不保证再次尝试成功；未自动创建新付费任务。"],
    capmonster_poll_timeout: ["求解查询超时", "本地查询预算已耗尽，不等于服务已确认求解失败；保留原任务回执，继续不会重置预算。"],
    network_unavailable: ["网络连接失败", "当前请求未取得响应；请结合阶段判断，不能据此认定为验证码失败。"],
    upstream_unavailable: ["上游服务异常", "当前请求返回上游错误；请结合阶段判断，不能据此认定为验证码失败。"],
    capmonster_attempt_already_used: ["付费任务保护", "已有创建中、失败或已消费的回执；本任务不再创建新的付费求解，需核对原始日志。"]
  };
  const reason = ["human_required", "partial", "needs_check", "failed"].includes(state) && Object.hasOwn(reasons, result.error)
    ? reasons[result.error] : null;
  return {label: reason ? reason[0] : (stateLabels[state] || state),
    detail: reason ? result.error + "；" + reason[1] : (result.error || "")};
}

function rollingNumber(node, value) {
  const text = String(value);
  if (node.dataset.value === text && node.children.length) return;
  const old = node.dataset.value || "";
  node.dataset.value = text;
  if (node.children.length !== text.length || [...text].some((char, index) =>
      node.children[index]?.classList.contains("rolling-digit") !== /\d/.test(char))) {
    node.replaceChildren(...[...text].map(char => {
      const cell = document.createElement("span");
      if (/\d/.test(char)) {
        cell.className = "rolling-digit";
        const strip = document.createElement("span");
        strip.className = "rolling-strip";
        for (let digit = 0; digit < 10; digit++) {
          const row = document.createElement("span");
          row.textContent = String(digit);
          strip.append(row);
        }
        cell.append(strip);
      } else cell.textContent = char;
      return cell;
    }));
  }
  [...text].forEach((char, index) => {
    const cell = node.children[index];
    if (!/\d/.test(char)) { cell.textContent = char; return; }
    const strip = cell.querySelector(".rolling-strip");
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      strip.style.transform = "translateY(-" + Number(char) + "em)";
    } else if (old[index] !== char || !strip.style.transform) {
      requestAnimationFrame(() => requestAnimationFrame(() => {
        strip.style.transform = "translateY(-" + Number(char) + "em)";
      }));
    }
  });
}

function updateTaskReadout(job) {
  const total = Number.isSafeInteger(job.account_count) && job.account_count >= 0 ? job.account_count : 0;
  const done = Number.isSafeInteger(job.completed_count) && job.completed_count >= 0 ? Math.min(total, job.completed_count) : 0;
  rollingNumber($("#completedReadout"), done);
  rollingNumber($("#totalReadout"), total);
  $("#taskReadout").setAttribute("aria-label", "已完成 " + done + " / 总任务 " + total);
}

// One line per entry. A bare-address line may also be comma/space/semicolon
// separated, while a credential line (email----...) counts as exactly one.
function splitBatchTokens(value) {
  return String(value || "").split(/[\s,;]+/).map(token => token.trim()).filter(Boolean);
}

function batchEmailEntries(value) {
  const entries = [];
  for (const raw of String(value || "").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.includes("----")) entries.push(line);
    else entries.push(...splitBatchTokens(line));
  }
  return entries;
}

function updateBatchCounts() {
  const emails = batchEmailEntries($("#batchEmails").value);
  const proxies = String($("#batchProxies").value || "").split("\n").map(line => line.trim()).filter(Boolean);
  $("#batchEmailCount").textContent = emails.length + " / " + MAX_BATCH_ACCOUNTS;
  $("#batchProxyCount").textContent = proxies.length + " / " + MAX_BATCH_PROXIES;
  $("#batchEmailCount").classList.toggle("over", emails.length > MAX_BATCH_ACCOUNTS);
  $("#batchProxyCount").classList.toggle("over", proxies.length > MAX_BATCH_PROXIES);
  const counts = new Map();
  for (let index = 0; index < emails.length; index++) {
    const row = emails[index].split("----")[0].split("@")[0];
    const label = proxies.length ? "第 " + (index % proxies.length + 1) + " 条代理" : "直连";
    counts.set(label, (counts.get(label) || 0) + 1);
    void row;
  }
  $("#batchAssignment").textContent = emails.length
    ? "代理轮询分配（" + emails.length + " 个账号 / " + proxies.length + " 条代理）：" +
      [...counts].map(([label, count]) => label + " ×" + count).join("、")
    : "代理按行轮询分配：代理数量为 0 时全部直连。";
}

function updateBalanceReadout(balance) {
  if (typeof balance !== "number" || !Number.isFinite(balance) || balance < 0) throw new Error("余额响应无效");
  rollingNumber($("#balanceValue"), balance.toLocaleString("en-US", {useGrouping: false, minimumFractionDigits: 4, maximumFractionDigits: 6}));
  $("#balanceReadout").setAttribute("aria-label", "CapMonster 余额 " + balance);
  $("#balanceReadout").title = "CapMonster API 原值：" + balance;
}

async function loadBalance() {
  if (balanceLoading || Date.now() - balanceCheckedAt < 60000) return;
  balanceLoading = true;
  balanceCheckedAt = Date.now();
  try {
    const config = await api("/api/services/capmonster");
    if (!config.configured) throw new Error("尚未配置 CapMonster 密钥");
    const payload = await api("/api/services/capmonster/test", {method: "POST"});
    updateBalanceReadout(payload.balance);
  } catch (error) {
    rollingNumber($("#balanceValue"), "--");
    $("#balanceReadout").title = error.message;
    $("#balanceReadout").setAttribute("aria-label", "CapMonster 余额不可用：" + error.message);
  } finally { balanceLoading = false; }
}

async function api(path, options = {}) {
  const config = {...options, cache: "no-store", headers: {...options.headers}};
  if (config.body) {
    config.headers["Content-Type"] = "application/json";
    config.body = JSON.stringify(config.body);
  }
  const response = await fetch(path, config);
  let payload;
  try { payload = await response.json(); }
  catch { throw new Error("服务响应无效（HTTP " + response.status + "）"); }
  if (!response.ok || payload.ok === false) throw new Error(payload.error || "HTTP " + response.status);
  return payload;
}

function toast(message, failed = false) {
  const node = document.createElement("div");
  node.className = "toast" + (failed ? " error" : "");
  node.textContent = message;
  $("#toastStack").append(node);
  setTimeout(() => node.remove(), 4500);
}

async function runAction(button, action) {
  button.disabled = true;
  try { await action(); }
  catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}

async function loadHealth() {
  const health = await api("/api/health");
  $("#sideHealthText").textContent = health.ok ? "基础服务正常" : "基础服务异常";
  $("#sideHealthDot").classList.toggle("ok", health.ok);
  $("#runtimeDetails").replaceChildren();
  for (const [name, ok] of Object.entries(health.checks)) {
    const node = document.createElement("div");
    node.textContent = name + ": " + (ok ? "正常" : "异常");
    $("#runtimeDetails").append(node);
  }
}

function renderAccounts() {
  const query = $("#poolSearch").value.trim().toLowerCase();
  const rows = accounts.filter(row => row.email.toLowerCase().includes(query));
  $("#accountCount").textContent = rows.length + " 个邮箱";
  $("#poolEmpty").classList.toggle("hidden", rows.length > 0);
  $("#poolTableBody").innerHTML = rows.map(row => {
    const email = escapeHtml(row.email);
    return '<tr><td>' + email + '</td><td>' + escapeHtml(row.mailbox_kind) +
      '</td><td>' + escapeHtml(stateLabels[row.state] || row.state) + (row.connectivity_status === "logicc_ready" ? " · 模型检测通过" : "") +
      '</td><td>' + (row.has_platform_password ? '<button class="secondary compact" data-password="' + email + '">•••••••• · 查看</button>' : '未保存') + '</td></tr>';
  }).join("");
}

async function loadAccounts() {
  accounts = (await api("/api/accounts/managed")).accounts;
  renderAccounts();
}

async function loadJobs() {
  const jobs = (await api("/api/jobs")).jobs;
  $("#jobsTableBody").innerHTML = jobs.map(job => {
    const id = escapeHtml(job.id);
    return "<tr><td>" + escapeHtml(job.label || job.id) + "</td><td>" + escapeHtml(resultPresentation(job.state, {error: job.result_error}).label) +
      "</td><td>" + escapeHtml(job.progress) + "%</td><td>" + escapeHtml(job.success_count) +
      " / " + escapeHtml(job.account_count) + '</td><td><button class="secondary compact" data-job="' +
      id + '">详情</button>' + (job.resume_available ?
      ' <button class="secondary compact" data-resume="' + id + '">继续原会话</button>' : "") +
      (job.state === "running" || job.resume_available ?
      ' <button class="danger compact" data-stop="' + id + '">停止/核对</button>' : "") + "</td></tr>";
  }).join("") || '<tr><td colspan="5">暂无任务</td></tr>';
}

function renderBatchTable(batch) {
  const rows = Array.isArray(batch.accounts) ? batch.accounts : [];
  $("#batchTableBody").innerHTML = rows.map(row => {
    const presentation = resultPresentation(row.state, row);
    const state = presentation.label;
    const detail = row.error ? presentation.detail : (row.integration_status ? (integrationLabels[row.integration_status] || row.integration_status) : "");
    return "<tr><td>" + escapeHtml(row.email) + "</td><td>" + escapeHtml(row.proxy_region || "DIRECT") +
      "</td><td>" + escapeHtml(state) + "</td><td>" + escapeHtml(row.step || "") +
      "</td><td>" + escapeHtml(detail) + "</td></tr>";
  }).join("") || '<tr><td colspan="5">尚未启动批次</td></tr>';
  const running = batch.state === "running" || batch.state === "queued";
  $("#batchTableSummary").textContent = rows.length
    ? (stateLabels[batch.headline_state] || batch.headline_state || batch.state) + " · 成功 " + batch.success_count +
      " · 失败 " + batch.failed_count + " · 待处理 " + batch.pending_count +
      " · 未启动 " + (batch.queued_count || 0)
    : "尚未启动批次";
  $("#stopBatchRun").disabled = !running || !batch.id;
}

async function loadBatch() {
  if (batchLoading) return;
  batchLoading = true;
  try {
    if (!activeBatchId) {
      const batches = (await api("/api/batches")).batches;
      const running = batches.find(batch => batch.state === "running" || batch.state === "queued");
      activeBatchId = (running || batches[0])?.id || "";
    }
    if (!activeBatchId) { updateBatchCounts(); return; }
    const batch = (await api("/api/batches/" + encodeURIComponent(activeBatchId) + "?tail=500")).batch;
    updateTaskReadout(batch);
    renderBatchTable(batch);
    const output = $("#worklogOutput");
    const follow = output.scrollHeight - output.scrollTop - output.clientHeight < 30;
    output.textContent = (Array.isArray(batch.logs) ? batch.logs.join("\n") : String(batch.logs || "等待批次日志…")).slice(-100000);
    $("#worklogStatus").textContent = (stateLabels[batch.headline_state] || batch.headline_state || batch.state) +
      " · " + batch.id.slice(0, 8) +
      " · " + batch.account_count + " 账号 / 并发 " + batch.worker_limit + " / " + batch.proxy_count + " 代理";
    if (follow) output.scrollTop = output.scrollHeight;
  } finally {
    batchLoading = false;
  }
}

async function loadResults() {
  const rows = (await api("/api/results")).results;
  $("#resultsTableBody").innerHTML = rows.map(row => "<tr><td>" + escapeHtml(row.email) +
    "</td><td>" + escapeHtml(resultPresentation(row.status, row).label) + " · " + escapeHtml(integrationLabels[row.integration_status] || "未导入") + "</td><td>" + escapeHtml(row.method) +
    "</td><td>" + escapeHtml(row.job_id) + "</td></tr>").join("") ||
    '<tr><td colspan="4">暂无结果</td></tr>';
}

async function loadSettings() {
  const payload = await api("/api/settings");
  $$("[data-setting]").forEach(node => {
    node.value = payload.settings[node.dataset.setting] ?? "";
    if (node.type === "password") node.placeholder = payload.secret_configured[node.dataset.setting] ? "已配置，留空保留" : "尚未配置";
  });
  await Promise.all([loadServiceSettings(), loadProxies()]);
}

async function loadServiceSettings() {
  const [cap, integration] = await Promise.all([api("/api/services/capmonster"), api("/api/services/logicc2api")]);
  $("#capmonsterEnabled").checked = cap.enabled;
  $("#capmonsterKey").value = "";
  $("#capmonsterKey").placeholder = cap.configured ? "已加密配置，留空保留" : "尚未配置";
  $("#logicc2apiEnabled").checked = integration.enabled;
  $("#logicc2apiBaseUrl").value = integration.base_url;
}

async function loadProxies() {
  const rows = (await api("/api/proxies")).proxies;
  $("#proxyTableBody").innerHTML = rows.map(row => '<tr><td>' + escapeHtml(row.label) + '</td><td>' +
    escapeHtml(row.last_check ? (row.last_check.ok ? "HTTPS 正常 · " + row.last_check.ip : row.last_check.error || "目标响应异常") : "未检测") +
    '</td><td><button class="secondary compact" data-proxy-check="' + escapeHtml(row.id) + '">检测连接</button></td></tr>').join("") ||
    '<tr><td colspan="3">尚未导入固定代理</td></tr>';
}

async function routeTo(view) {
  if (!viewNames[view]) view = "pool";
  if ($("#passwordDialog").open) $("#passwordDialog").close();
  activeView = view;
  $$(".view").forEach(node => node.classList.toggle("active", node.dataset.view === view));
  $$(".nav-item").forEach(node => node.classList.toggle("active", node.dataset.nav === view));
  $("#pageCrumb").textContent = viewNames[view];
  $("#sidebar").classList.remove("open");
  $("#sidebarToggle").setAttribute("aria-expanded", "false");
  history.replaceState(null, "", "#" + view);
  try {
    if (view === "pool") await loadAccounts();
    if (view === "launch") await Promise.all([loadBatch(), loadBalance()]);
    if (view === "jobs") await loadJobs();
    if (view === "results") await loadResults();
    if (view === "settings") await Promise.all([loadSettings(), loadHealth()]);
  } catch (error) { toast(error.message, true); }
}

document.addEventListener("click", event => {
  const button = event.target.closest("button, a[data-nav]");
  if (!button || button.disabled) return;
  if (button.dataset.nav) {
    event.preventDefault();
    void routeTo(button.dataset.nav);
  }
  if (button.dataset.close) $("#" + button.dataset.close).close();
  if (button.dataset.password) void runAction(button, async () => {
    const serial = ++passwordRequest;
    $("#passwordEmail").textContent = button.dataset.password;
    $("#passwordOutput").textContent = "正在读取…";
    $("#passwordDialog").showModal();
    try {
      const payload = await api("/api/accounts/" + encodeURIComponent(button.dataset.password) + "/platform-password", {method: "POST", body: {}});
      if (serial === passwordRequest && $("#passwordDialog").open) $("#passwordOutput").textContent = payload.password;
    } catch (error) {
      if (serial === passwordRequest && $("#passwordDialog").open) $("#passwordOutput").textContent = error.message;
    }
  });
  if (button.dataset.job) void runAction(button, async () => {
    const job = (await api("/api/jobs/" + encodeURIComponent(button.dataset.job))).job;
    $("#jobLog").textContent = job.logs || "暂无日志";
    const result = (job.results || []).at(-1) || {};
    const presentation = resultPresentation(job.state, result);
    $("#jobState").textContent = presentation.label + " · " +
      (result.step || job.registration_step || "") + " · " + presentation.detail +
      " · 账号认证：" + (result.registration_ok ? "已确认" : "未确认") +
      " · 入驻：" + (result.onboarding_ok ? "已确认" : "未确认") + " · " +
      (integrationLabels[result.integration_status] || "未导入") + " " + (result.integration_error || "");
    $("#jobDownloads").replaceChildren();
    for (const kind of ["log", "results"]) {
      const link = document.createElement("a");
      link.className = "secondary";
      link.href = "/api/jobs/" + encodeURIComponent(job.id) + "/download/" + kind;
      link.textContent = kind === "log" ? "下载日志" : "下载结果";
      $("#jobDownloads").append(link);
    }
    if (result.registration_ok && result.onboarding_ok) {
      const action = document.createElement("button");
      action.className = "secondary";
      action.dataset.integrate = job.id;
      action.textContent = "导入/检测 logicc2api";
      $("#jobDownloads").append(action);
    }
    $("#jobDialog").showModal();
  });
  if (button.dataset.resume) void runAction(button, async () => {
    const job = (await api("/api/jobs/" + encodeURIComponent(button.dataset.resume))).job;
    const result = (job.results || []).at(-1) || {};
    resumeJobId = job.id;
    $("#resumeForm").reset();
    const captcha = job.state === "human_required" &&
      ["captcha_required", "captcha_already_consumed"].includes(result.error);
    const code = job.state === "code_required";
    $("#resumeCaptchaLabel").classList.toggle("hidden", !captcha);
    $("#resumeCodeLabel").classList.toggle("hidden", !code);
    $("#resumeResendLabel").classList.toggle("hidden", !code);
    $("#resumeCaptcha").required = false;
    const presentation = resultPresentation(job.state, result);
    $("#resumeExplanation").textContent = presentation.label + "：" + presentation.detail +
      (captcha ? "。可使用已配置的 CapMonster；不得使用抓包里的旧材料。" : "。先核对原会话，再从原阶段继续。");
    $("#resumeDialog").showModal();
  });
  if (button.dataset.stop) void runAction(button, async () => {
    await api("/api/jobs/" + encodeURIComponent(button.dataset.stop) + "/stop", {method: "POST"});
    await loadJobs();
  });
  if (button.dataset.proxyCheck) void runAction(button, async () => {
    const payload = await api("/api/proxies/" + encodeURIComponent(button.dataset.proxyCheck) + "/test", {method: "POST"});
    await loadProxies();
    toast(payload.check.ok ? "代理与注册入口连接正常" : payload.check.error || "代理目标响应异常", !payload.check.ok);
  });
  if (button.dataset.integrate) void runAction(button, async () => {
    const payload = await api("/api/jobs/" + encodeURIComponent(button.dataset.integrate) + "/logicc2api", {method: "POST"});
    toast("已导入，模型检测通过：" + payload.integration_models + " 个模型");
    $("#jobDialog").close();
    await loadJobs();
  });
});

$("#passwordDialog").addEventListener("close", () => {
  ++passwordRequest;
  $("#passwordOutput").textContent = "";
  $("#passwordEmail").textContent = "";
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden && $("#passwordDialog").open) $("#passwordDialog").close();
});
$("#batchEmails").addEventListener("input", updateBatchCounts);
$("#batchProxies").addEventListener("input", updateBatchCounts);
$("#batchWorkers").addEventListener("input", () => {
  const value = Number($("#batchWorkers").value);
  $("#batchWorkerHint").textContent = Number.isFinite(value) && value >= 1 && value <= MAX_BATCH_WORKERS
    ? "1 – " + MAX_BATCH_WORKERS + "（当前 " + value + "）"
    : "1 – " + MAX_BATCH_WORKERS;
});
$("#sidebarToggle").addEventListener("click", () => {
  const open = $("#sidebar").classList.toggle("open");
  $("#sidebarToggle").setAttribute("aria-expanded", String(open));
});
$("#themeToggle").addEventListener("click", () => {
  const theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("logicc-theme", theme);
});
$("#poolSearch").addEventListener("input", renderAccounts);
$("#openImport").addEventListener("click", () => $("#importDialog").showModal());
$("#importDialog").addEventListener("close", () => { $("#importLines").value = ""; });
$("#importForm").addEventListener("submit", event => {
  event.preventDefault();
  void runAction($("#importForm button[type=submit]"), async () => {
    if ($("#importMode").value === "replace" && !confirm("替换会删除现有邮箱记录，确定继续？")) return;
    const payload = await api("/api/accounts/import", {method: "POST",
      body: {lines: $("#importLines").value, mode: $("#importMode").value}});
    $("#importDialog").close();
    toast("已导入 " + payload.imported + " 个邮箱");
    await loadAccounts();
  });
});
$("#protocolRunForm").addEventListener("submit", event => {
  event.preventDefault();
  void runAction($("#startProtocolRun"), async () => {
    const emails = batchEmailEntries($("#batchEmails").value);
    if (!emails.length) throw new Error("请粘贴至少一个注册邮箱");
    if (emails.length > MAX_BATCH_ACCOUNTS) throw new Error("单批最多 " + MAX_BATCH_ACCOUNTS + " 个邮箱");
    const proxies = $("#batchProxies").value.split("\n").map(line => line.trim()).filter(Boolean);
    if (proxies.length > MAX_BATCH_PROXIES) throw new Error("单批最多 " + MAX_BATCH_PROXIES + " 条代理");
    const workers = Number($("#batchWorkers").value);
    if (!Number.isSafeInteger(workers) || workers < 1 || workers > MAX_BATCH_WORKERS) {
      throw new Error("并发数必须在 1 到 " + MAX_BATCH_WORKERS + " 之间");
    }
    const payload = await api("/api/batches", {method: "POST", body: {
      emails: emails.join("\n"), proxies: proxies.join("\n"), workers,
      accept_terms: $("#registrationTerms").checked, method: "protocol"}});
    activeBatchId = payload.batch.id;
    $("#batchProxies").value = "";
    updateBatchCounts();
    const imported = payload.imported?.added || 0;
    toast("批量任务已启动：" + payload.batch.account_count + " 个账号 / 并发 " + workers +
      (imported ? " / 新导入 " + imported + " 个邮箱" : ""));
    await loadBatch();
    if (imported) await loadAccounts();
  });
});
$("#stopBatchRun").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  if (!activeBatchId) return;
  if (!confirm("停止会中断未完成的账号，已确认的注册不受影响。确定继续？")) return;
  const payload = await api("/api/batches/" + encodeURIComponent(activeBatchId) + "/stop", {method: "POST"});
  renderBatchTable(payload.batch);
  toast("已请求停止当前批次");
}));
$("#resumeForm").addEventListener("submit", event => {
  event.preventDefault();
  void runAction($("#resumeForm button[type=submit]"), async () => {
    await api("/api/jobs/" + encodeURIComponent(resumeJobId) + "/resume", {method: "POST",
      body: {captcha_token: $("#resumeCaptcha").value, code: $("#resumeCode").value,
             resend_code: $("#resumeResend").checked}});
    $("#resumeDialog").close();
    await loadJobs();
  });
});
$("#resumeDialog").addEventListener("close", () => {
  $("#resumeForm").reset();
  resumeJobId = "";
});
for (const [id, action] of Object.entries({refreshAccounts: loadAccounts, refreshJobs: loadJobs, refreshResults: loadResults, runtimeRefresh: loadHealth})) {
  $("#" + id).addEventListener("click", event => void runAction(event.currentTarget, action));
}
$$("[data-setting-panel]").forEach(button => button.addEventListener("click", () => {
  $$("[data-setting-panel]").forEach(node => node.classList.toggle("active", node === button));
  $$(".setting-panel[data-panel]").forEach(node => node.classList.toggle("active", node.dataset.panel === button.dataset.settingPanel));
}));
$("#importProxies").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  const payload = await api("/api/proxies/import", {method: "POST", body: {lines: $("#proxyLines").value}});
  $("#proxyLines").value = "";
  await loadProxies();
  toast("已追加 " + payload.added + " 条代理");
}));
$("#saveCapmonster").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  await api("/api/services/capmonster", {method: "PATCH", body: {enabled: $("#capmonsterEnabled").checked, client_key: $("#capmonsterKey").value}});
  await loadServiceSettings();
  balanceCheckedAt = 0;
  toast("CapMonster 已加密保存");
}));
$("#testCapmonster").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  const payload = await api("/api/services/capmonster/test", {method: "POST"});
  updateBalanceReadout(payload.balance);
  balanceCheckedAt = Date.now();
  $("#capmonsterResult").classList.remove("hidden");
  $("#capmonsterResult").textContent = "连接正常，余额 " + payload.balance + "；未创建付费任务";
}));
$("#saveLogicc2api").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  await api("/api/services/logicc2api", {method: "PATCH", body: {enabled: $("#logicc2apiEnabled").checked, base_url: $("#logicc2apiBaseUrl").value}});
  toast("自动导入配置已保存");
}));
$("#testLogicc2api").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  const payload = await api("/api/services/logicc2api/test", {method: "POST"});
  $("#logicc2apiResult").classList.remove("hidden");
  $("#logicc2apiResult").textContent = "本机管理 API 正常，已有 " + payload.account_count + " 个账号；未调用上游";
}));
$("#saveSettings").addEventListener("click", event => void runAction(event.currentTarget, async () => {
  const body = Object.fromEntries($$("[data-setting]").map(node => [node.dataset.setting, node.value]));
  await api("/api/settings", {method: "PATCH", body});
  await loadSettings();
  toast("配置已保存");
}));
for (const [id, path, output] of [["testRoxy", "/api/roxy/test", "#roxyTestResult"], ["testDomainMailbox", "/api/domain-mailbox/test", "#domainMailboxTestResult"]]) {
  $("#" + id).addEventListener("click", event => void runAction(event.currentTarget, async () => {
    const payload = await api(path, {method: "POST"});
    $(output).classList.remove("hidden");
    $(output).textContent = payload.ok ? "连接正常" : "连接失败";
  }));
}
void loadHealth().catch(error => toast(error.message, true));
void routeTo(location.hash.slice(1));
updateBatchCounts();
setInterval(() => {
  if (activeView === "launch" && !document.hidden) void loadBalance();
  if (activeView === "launch" && !document.hidden) void loadBatch().catch(error => { $("#worklogStatus").textContent = error.message; });
  if (activeView === "jobs" && !document.hidden) void loadJobs().catch(error => toast(error.message, true));
}, 4000);
