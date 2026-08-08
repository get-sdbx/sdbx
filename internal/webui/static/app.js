const tokenStorageKey = "sdbx.console.token:/";

function consumeFragmentToken() {
  const parameters = new URLSearchParams(location.hash.slice(1));
  const supplied = parameters.get("token") || "";
  if (/^[A-Za-z0-9_-]{43}$/.test(supplied)) {
    try {
      sessionStorage.setItem(tokenStorageKey, supplied);
    } catch {
      // The current navigation remains authenticated even when browser policy
      // disables session storage. A reload will require the URL again.
    }
    history.replaceState(null, "", `${location.pathname}${location.search}#overview`);
    return supplied;
  }
  return "";
}

function loadConsoleToken() {
  const supplied = consumeFragmentToken();
  if (supplied) return supplied;
  try {
    return sessionStorage.getItem(tokenStorageKey) || "";
  } catch {
    return "";
  }
}

let token = loadConsoleToken();

const state = {
  view: "overview",
  connected: false,
  summary: null,
  security: null,
  services: [],
  addons: [],
  settings: null,
  backups: [],
  diagnostics: null,
  audit: [],
  serviceFilter: "",
  serviceStatus: "all",
  addonFilter: "",
  addonStatus: "all",
  liveLogs: false,
  logTimer: null,
  logFailures: 0,
};

const viewMeta = {
  overview: ["Dashboard", "Overview", "Current status of your SDBX services."],
  services: ["Service management", "Services", "Check status, open apps, and review recent logs."],
  addons: ["Optional apps", "Addons", "Enable only the extra apps you want to use."],
  configuration: ["Setup", "Configuration", "Review and update your SDBX settings."],
  security: ["Protection", "Security", "Review access, encryption, VPN, and image protection."],
  backups: ["Recovery", "Backups", "Create and restore encrypted backups."],
  diagnostics: ["Troubleshooting", "Diagnostics", "Check the host, services, storage, network, and VPN."],
  audit: ["Activity", "Audit", "Review recent administrator actions."],
};

function apiPath(path) {
  return path.startsWith("/") ? path : `/${path}`;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function safeRouteURL(value) {
  try {
    const route = new URL(String(value ?? ""));
    return route.protocol === "https:" ? route.href : "";
  } catch {
    return "";
  }
}

function safeStatusClass(status) {
  if (["running", "healthy", "passed", "succeeded"].includes(status)) return "is-good";
  if (["starting", "warning", "started"].includes(status)) return "is-warn";
  if (["failed", "unhealthy", "exited", "dead"].includes(status)) return "is-bad";
  return "";
}

function safeLauncherIcon(value) {
  const token = String(value || "").toLowerCase();
  return /^[a-z][a-z0-9-]{0,31}$/.test(token) ? token : "";
}

function formatSize(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let scaled = value / 1024;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(scaled >= 10 ? 0 : 1)} ${units[unit]}`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatSettingValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  if (value === true) return "Enabled";
  if (value === false) return "Disabled";
  return value ?? "";
}

async function api(path, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };
  const method = options.method || "GET";
  if (token) {
    headers["X-SDBX-Token"] = token;
  }
  let response;
  try {
    response = await fetch(apiPath(path), {
      ...options,
      method,
      headers,
      credentials: "same-origin",
    });
  } catch {
    setConnection(false);
    throw new Error("The SDBX management service is unreachable.");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 403 && data.code === "invalid_token") {
      try {
        sessionStorage.removeItem(tokenStorageKey);
      } catch {
        // Browser storage may be disabled; the in-memory token is still reset.
      }
      token = "";
      showAccessGate();
    }
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      setConnection(false);
    }
    const message = data.error || "The operation could not be completed.";
    const error = new Error(message);
    error.code = data.code || "request_failed";
    error.status = response.status;
    error.silent = response.status === 403 && data.code === "invalid_token";
    throw error;
  }
  setConnection(true);
  markUpdated();
  return data;
}

function showAccessGate() {
  document.getElementById("access-gate").hidden = false;
  document.getElementById("app-shell").hidden = true;
  document.querySelector(".skip-link").hidden = true;
  document.title = "Authorization required · SDBX";
}

function showConsole() {
  document.getElementById("access-gate").hidden = true;
  document.getElementById("app-shell").hidden = false;
  document.querySelector(".skip-link").hidden = false;
  document.title = "SDBX Dashboard";
}

function setConnection(connected) {
  state.connected = connected;
  const card = document.getElementById("connection-card");
  const label = document.getElementById("connection-label");
  const banner = document.getElementById("offline-banner");
  card.classList.toggle("is-offline", !connected);
  label.textContent = connected ? "Connected" : "Unavailable";
  banner.hidden = connected;
  document.querySelectorAll("[data-stack], [data-addon-action], [data-setting-save], [data-backup-action], #create-backup")
    .forEach((element) => {
      element.disabled = !connected;
    });
}

function markUpdated() {
  const previewLabel = document.querySelector('meta[name="sdbx-preview-label"]')?.content.trim();
  if (previewLabel) {
    document.getElementById("last-updated").textContent = previewLabel;
    return;
  }
  document.getElementById("last-updated").textContent =
    `Updated ${new Intl.DateTimeFormat(undefined, { timeStyle: "medium" }).format(new Date())}`;
}

function toast(title, detail = "", error = false) {
  const region = document.getElementById("toast-region");
  const item = document.createElement("div");
  item.className = `toast${error ? " is-error" : ""}`;
  item.innerHTML = `<strong>${escapeHTML(title)}</strong>${detail ? `<span>${escapeHTML(detail)}</span>` : ""}`;
  region.append(item);
  window.setTimeout(() => item.remove(), 5000);
}

function reportError(error, fallback = "Operation failed") {
  if (error?.silent) return;
  const detail = error?.code ? `Reference: ${error.code}` : error?.message || "";
  toast(fallback, detail, true);
  document.getElementById("message").textContent = `${fallback}. ${detail}`;
}

function metric(label, value) {
  return `<article class="metric"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></article>`;
}

function renderOverview() {
  const summary = state.summary;
  const security = state.security;
  if (!summary) return;
  document.getElementById("overview-running").textContent = summary.runningServices;
  document.getElementById("overview-total").textContent = `of ${summary.totalServices} services running`;
  document.getElementById("overview-domain").textContent = `${summary.projectId} · ${summary.domain}`;
  const percentage = summary.totalServices
    ? Math.round((summary.runningServices / summary.totalServices) * 100)
    : 0;
  document.getElementById("runtime-progress").style.width = `${percentage}%`;
  document.getElementById("overview-metrics").innerHTML = [
    metric("Enabled addons", `${summary.enabledAddons} / ${summary.totalAddons}`),
    metric("Encrypted backups", summary.backups),
    metric("Configured services", security?.lockedServices ?? summary.totalServices),
    metric("Exposure", security?.exposureMode ?? "—"),
  ].join("");

  const warnings = summary.warnings || [];
  document.getElementById("warning-count").textContent = warnings.length;
  document.getElementById("warning-list").innerHTML = warnings.length
    ? warnings.map((warning) => `
      <div class="compact-item">
        <strong>${escapeHTML(warning.service || "Catalog")}</strong>
        <span>${escapeHTML(warning.message)}</span>
      </div>`).join("")
    : '<div class="empty-state compact">No catalog warnings.</div>';
}

function launcherAuthLabel(auth) {
  return ({
    "admin-only": "Admin sign-in",
    protected: "Authelia",
    "native-auth": "App sign-in",
    public: "Public",
  })[auth] || "Sign-in set";
}

function launcherMonogram(service) {
  const token = safeLauncherIcon(service.launcher?.icon) || service.name || "sdbx";
  return token.replace(/[^a-z0-9]/g, "").slice(0, 2).toUpperCase() || "SX";
}

function launcherCard(service) {
  const route = safeRouteURL(service.route);
  const running = Boolean(service.running);
  const unhealthy = running && service.health &&
    !["healthy", "none", "no healthcheck"].includes(String(service.health).toLowerCase());
  const stateLabel = running ? (unhealthy ? "degraded" : "online") : "offline";
  const content = `
    <span class="launcher-icon" aria-hidden="true">${escapeHTML(launcherMonogram(service))}</span>
    <span class="launcher-copy">
      <strong>${escapeHTML(service.name)}</strong>
      <small>${escapeHTML(service.launcher?.subtitle || service.description || service.category)}</small>
    </span>
    <span class="launcher-meta">
      <span class="launcher-state ${running ? (unhealthy ? "is-warn" : "is-online") : ""}">${escapeHTML(stateLabel)}</span>
      <span>${escapeHTML(launcherAuthLabel(service.routeAuth))}</span>
    </span>`;
  if (running && route) {
    return `<a class="launcher-card" href="${escapeHTML(route)}" target="_blank" rel="noopener noreferrer" aria-label="Open ${escapeHTML(service.name)} in a new tab">${content}<span class="launcher-arrow" aria-hidden="true">↗</span></a>`;
  }
  return `<button class="launcher-card is-offline" data-nav="services" aria-label="${escapeHTML(service.name)} is not running; inspect services">${content}<span class="launcher-arrow" aria-hidden="true">→</span></button>`;
}

function renderLauncher(error = "") {
  const root = document.getElementById("service-launcher");
  if (error) {
    root.innerHTML = `<div class="empty-state launcher-error">Service status unavailable. The rest of the dashboard remains usable. <button class="inline-link" data-nav="services">View services</button></div>`;
    return;
  }
  const services = state.services.filter((service) =>
    service.launcher?.enabled && safeRouteURL(service.route));
  if (!services.length) {
    root.innerHTML = '<div class="empty-state">No apps with a web interface are enabled.</div>';
    return;
  }
  const groupOrder = ["media", "downloads", "management", "utilities"];
  const labels = {
    media: "Media",
    downloads: "Downloads",
    management: "Management",
    utilities: "Utilities",
  };
  root.innerHTML = groupOrder.map((group) => {
    const entries = services.filter((service) => service.launcher.group === group);
    if (!entries.length) return "";
    return `
      <section class="launcher-group" aria-labelledby="launcher-group-${escapeHTML(group)}">
        <div class="launcher-group-heading">
          <h3 id="launcher-group-${escapeHTML(group)}">${escapeHTML(labels[group])}</h3>
          <span>${entries.length.toString().padStart(2, "0")}</span>
        </div>
        <div class="launcher-grid">${entries.map(launcherCard).join("")}</div>
      </section>`;
  }).join("");
}

async function loadLauncher() {
  try {
    const data = await api("/api/status");
    state.services = data.services || [];
    renderLauncher();
    renderServices();
  } catch (error) {
    renderLauncher(error?.message || "service status unavailable");
  }
}

async function loadOverview() {
  // Put the app launcher on screen before loading secondary dashboard data.
  await loadLauncher();
  const [summary, security] = await Promise.all([
    api("/api/summary"),
    api("/api/security"),
  ]);
  state.summary = summary;
  state.security = security;
  renderOverview();
}

function statusPill(text) {
  const normalized = String(text || "unknown").toLowerCase();
  return `<span class="status-pill ${safeStatusClass(normalized)}">${escapeHTML(normalized)}</span>`;
}

function serviceMatches(service) {
  const query = state.serviceFilter.toLowerCase();
  if (query && !`${service.name} ${service.category} ${service.image}`.toLowerCase().includes(query)) {
    return false;
  }
  if (state.serviceStatus === "running") return service.running;
  if (state.serviceStatus === "stopped") return !service.running;
  return true;
}

function renderServices() {
  const services = state.services.filter(serviceMatches);
  const root = document.getElementById("services");
  const options = ['<option value="">All active services</option>'].concat(
    state.services.map((service) =>
      `<option value="${escapeHTML(service.name)}">${escapeHTML(service.name)}</option>`),
  );
  const currentLogService = document.getElementById("log-service").value;
  document.getElementById("log-service").innerHTML = options.join("");
  if (state.services.some((service) => service.name === currentLogService)) {
    document.getElementById("log-service").value = currentLogService;
  }
  if (!services.length) {
    root.innerHTML = '<div class="empty-state">No services match this filter.</div>';
    return;
  }
  root.innerHTML = `
    <div class="table-row table-head">
      <span>Service</span><span>Status</span><span>Health</span><span>Address</span><span>Logs</span>
    </div>
    ${services.map((service) => {
      const route = safeRouteURL(service.route);
      return `
        <div class="table-row">
          <div class="service-name">
            <strong>${escapeHTML(service.name)}</strong>
            <small>${escapeHTML(service.category)} · definition ${escapeHTML(service.definitionVersion || "—")}</small>
          </div>
          <div>${statusPill(service.running ? "running" : service.status || "stopped")}</div>
          <div>${statusPill(service.health || (service.present ? "no healthcheck" : "not created"))}</div>
          ${route
            ? `<a class="route-link" href="${escapeHTML(route)}" target="_blank" rel="noopener noreferrer">${escapeHTML(route)}</a>`
            : '<span class="route-link">Internal only</span>'}
          <button class="button button-small" data-service-log="${escapeHTML(service.name)}">Inspect</button>
        </div>`;
    }).join("")}`;
}

async function loadServices() {
  const data = await api("/api/status");
  state.services = data.services || [];
  renderServices();
  renderLauncher();
}

function scheduleLogs() {
  window.clearTimeout(state.logTimer);
  if (!state.liveLogs) return;
  const delay = Math.min(30000, 5000 * Math.max(1, state.logFailures));
  state.logTimer = window.setTimeout(async () => {
    try {
      await loadLogs(false);
      state.logFailures = 0;
    } catch {
      state.logFailures += 1;
    }
    scheduleLogs();
  }, delay);
}

async function loadLogs(announce = true) {
  const service = document.getElementById("log-service").value;
  const data = await api(`/api/logs?tail=200&service=${encodeURIComponent(service)}`);
  const logs = document.getElementById("logs");
  logs.textContent = data.logs || "No log output was returned.";
  if (state.liveLogs) logs.scrollTop = logs.scrollHeight;
  document.getElementById("log-meta").textContent =
    `${service || "All active services"} · maximum 200 lines · ${state.liveLogs ? "follow mode on" : "follow mode off"}`;
  if (announce) toast("Logs refreshed", service || "All active services");
}

function addonMatches(addon) {
  const query = state.addonFilter.toLowerCase();
  if (query && !`${addon.name} ${addon.description} ${addon.category}`.toLowerCase().includes(query)) {
    return false;
  }
  if (state.addonStatus === "enabled") return addon.enabled;
  if (state.addonStatus === "available") return !addon.enabled;
  return true;
}

function renderAddons() {
  const addons = state.addons.filter(addonMatches);
  const root = document.getElementById("addons");
  if (!addons.length) {
    root.innerHTML = '<div class="empty-state">No addons match this filter.</div>';
    return;
  }
  root.innerHTML = addons.map((addon) => {
    const action = addon.enabled ? "disable" : "enable";
    return `
      <article class="addon-card ${addon.enabled ? "is-enabled" : ""}">
        <span class="status-pill ${addon.enabled ? "is-good" : ""}">${addon.enabled ? "enabled" : "available"}</span>
        <h2>${escapeHTML(addon.name)}</h2>
        <p>${escapeHTML(addon.description || "Embedded addon definition.")}</p>
        <div class="addon-footer">
          <span class="category-pill">${escapeHTML(addon.category || "utility")}</span>
          <button class="button button-small ${addon.enabled ? "button-danger" : ""}"
            data-addon-action="${action}" data-addon-name="${escapeHTML(addon.name)}">
            ${addon.enabled ? "Disable" : "Enable"}
          </button>
        </div>
      </article>`;
  }).join("");
  setConnection(state.connected);
}

async function loadAddons() {
  const data = await api("/api/addons");
  state.addons = data.addons || [];
  renderAddons();
}

function settingControl(field, value, controlID) {
  const key = escapeHTML(field.key);
  if (!field.editable) {
    return `<span class="setting-value">${escapeHTML(formatSettingValue(value) || "—")}</span>`;
  }
  if (field.type === "select") {
    const options = (field.options || []).map((option) =>
      `<option value="${escapeHTML(option)}" ${option === value ? "selected" : ""}>${escapeHTML(option)}</option>`,
    ).join("");
    return `<select id="${controlID}" data-setting-input="${key}">${options}</select>`;
  }
  if (field.type === "boolean") {
    return `<input id="${controlID}" type="checkbox" data-setting-input="${key}" ${value ? "checked" : ""}>`;
  }
  const inputType = field.type === "number" ? "number" : "text";
  return `<input id="${controlID}" type="${inputType}" data-setting-input="${key}" value="${escapeHTML(formatSettingValue(value))}">`;
}

function settingValue(input) {
  if (!input) return "";
  if (input.type === "checkbox") return input.checked ? "true" : "false";
  return input.value;
}

function renderSettings() {
  const documentData = state.settings;
  const root = document.getElementById("settings");
  if (!documentData) {
    root.innerHTML = '<div class="error-state">Configuration metadata is unavailable.</div>';
    return;
  }
  const groups = new Map();
  for (const field of documentData.fields || []) {
    if (!groups.has(field.group)) groups.set(field.group, []);
    groups.get(field.group).push(field);
  }
  root.innerHTML = Array.from(groups.entries()).map(([group, fields], index) => `
    <section class="settings-group">
      <header>
        <p class="section-label">Group ${String(index + 1).padStart(2, "0")}</p>
        <h2>${escapeHTML(group)}</h2>
      </header>
      <div class="settings-grid">
        ${fields.map((field, fieldIndex) => {
          const controlID = `setting-${index}-${fieldIndex}`;
          return `
          <div class="setting">
            <label for="${controlID}">${escapeHTML(field.label)}</label>
            ${settingControl(field, documentData.settings?.[field.key], controlID)}
            ${field.editable
              ? `<button class="button button-small" data-setting-save="${escapeHTML(field.key)}">Save</button>`
              : ""}
          </div>`;
        }).join("")}
      </div>
    </section>`).join("");
  setConnection(state.connected);
}

async function loadSettings() {
  state.settings = await api("/api/config");
  renderSettings();
}

function evidenceCard(title, detail, verified) {
  return `
    <article class="evidence-card">
      <span class="evidence-status ${verified ? "" : "is-warn"}">
        <i class="evidence-dot"></i>${verified ? "verified" : "review"}
      </span>
      <h3>${escapeHTML(title)}</h3>
      <p>${escapeHTML(detail)}</p>
    </article>`;
}

function renderSecurity() {
  const report = state.security;
  if (!report) return;
  const checks = [
    [report.projectVerified, "Project integrity", `Configuration verified; ${report.lockedServices} services configured.`],
    [report.generatedFilesVerified, "Generated files", "SDBX-managed files have not changed unexpectedly."],
    [report.immutableImages === report.lockedServices, "Fixed image versions", `${report.immutableImages} of ${report.lockedServices} container images use fixed versions.`],
    [report.httpsRequired, "Encrypted routes", `${report.exposureMode} exposure via ${report.tlsProvider || "managed"} TLS.`],
    [!report.vpnEnabled || report.downloadVpnEnforced, "Download protection", report.vpnEnabled ? "qBittorrent traffic is routed through Gluetun." : "VPN was deliberately disabled for this project."],
    [Object.keys(report.routeAuth || {}).length > 0, "Sign-in rules", "Every public app has a defined sign-in policy."],
  ];
  const passed = checks.filter(([verified]) => verified).length;
  const hero = document.getElementById("security-hero");
  hero.classList.toggle("is-degraded", passed !== checks.length);
  hero.querySelector("h2").textContent = passed === checks.length
    ? "All declared controls verified"
    : `${checks.length - passed} control${checks.length - passed === 1 ? "" : "s"} need review`;
  hero.querySelector(".security-score").textContent = `${passed}/${checks.length}`;
  document.getElementById("security-evidence").innerHTML =
    checks.map(([verified, title, detail]) => evidenceCard(title, detail, verified)).join("");
  const labels = {
    "admin-only": "Admin only",
    protected: "Authelia protected",
    "native-auth": "Native auth",
    public: "Public",
  };
  document.getElementById("auth-distribution").innerHTML =
    Object.entries(labels).map(([key, label]) => `
      <div class="auth-cell">
        <span>${escapeHTML(label)}</span>
        <strong>${escapeHTML(report.routeAuth?.[key] || 0)}</strong>
      </div>`).join("");
}

async function loadSecurity() {
  state.security = await api("/api/security");
  renderSecurity();
}

function renderBackups() {
  const root = document.getElementById("backups");
  if (!state.backups.length) {
    root.innerHTML = '<div class="empty-state">No encrypted recovery archives yet.</div>';
    return;
  }
  root.innerHTML = `
    <div class="table-row table-head backup-row">
      <span>Archive</span><span>Created</span><span>Size</span><span>Actions</span>
    </div>
    ${state.backups.map((backup) => `
      <div class="table-row backup-row">
        <div class="service-name"><strong>${escapeHTML(backup.name)}</strong><small>age encrypted</small></div>
        <span>${escapeHTML(formatDate(backup.timestamp))}</span>
        <span>${escapeHTML(formatSize(backup.size))}</span>
        <div>
          <button class="button button-small" data-backup-action="restore" data-backup-name="${escapeHTML(backup.name)}">Restore</button>
          <button class="button button-small button-danger" data-backup-action="delete" data-backup-name="${escapeHTML(backup.name)}">Delete</button>
        </div>
      </div>`).join("")}`;
  setConnection(state.connected);
}

async function loadBackups() {
  const data = await api("/api/backups");
  state.backups = data.backups || [];
  renderBackups();
}

function renderDiagnostics() {
  const report = state.diagnostics;
  if (!report) return;
  document.getElementById("diagnostic-summary").innerHTML = [
    metric("Overall", report.healthy ? "Healthy" : "Action needed"),
    metric("Passed", report.summary?.passed ?? 0),
    metric("Failed", report.summary?.failed ?? 0),
  ].join("").replaceAll('class="metric"', 'class="diagnostic-stat"');
  const checks = report.checks || [];
  document.getElementById("diagnostics").innerHTML = `
    <div class="table-row table-head diagnostic-row">
      <span>Check</span><span>Status</span><span>Result</span><span>Duration</span>
    </div>
    ${checks.map((check) => `
      <div class="table-row diagnostic-row">
        <strong>${escapeHTML(check.name)}</strong>
        ${statusPill(check.status)}
        <span>${escapeHTML(check.message)}</span>
        <span>${escapeHTML(`${check.durationMs} ms`)}</span>
      </div>`).join("")}`;
}

async function runDiagnostics() {
  const button = document.getElementById("run-diagnostics");
  button.disabled = true;
  button.textContent = "Running checks…";
  document.getElementById("diagnostics").innerHTML = `
    <div class="skeleton-list" aria-label="Running diagnostics"><i></i><i></i><i></i><i></i></div>`;
  try {
    state.diagnostics = await api("/api/diagnostics");
    renderDiagnostics();
    toast("Diagnostics complete", state.diagnostics.healthy ? "All checks passed." : "Some checks require attention.");
  } finally {
    button.disabled = !state.connected;
    button.textContent = "Run checks";
  }
}

function renderAudit() {
  const root = document.getElementById("audit-events");
  if (!state.audit.length) {
    root.innerHTML = '<div class="empty-state">No privileged operation events recorded yet.</div>';
    return;
  }
  root.innerHTML = `
    <div class="table-row table-head audit-row">
      <span>Time</span><span>Actor</span><span>Operation</span><span>Outcome</span><span>Status</span>
    </div>
    ${state.audit.map((event) => `
      <div class="table-row audit-row">
        <span>${escapeHTML(formatDate(event.timestamp))}</span>
        <span>${escapeHTML(event.actor || "unknown")}</span>
        <strong>${escapeHTML(event.operation)}</strong>
        ${statusPill(event.outcome)}
        <span>${escapeHTML(event.status || "—")}</span>
      </div>`).join("")}`;
}

async function loadAudit() {
  const data = await api("/api/audit?limit=100");
  state.audit = data.events || [];
  renderAudit();
}

async function loadView(view, force = false) {
  try {
    if (view === "overview" && (force || !state.summary)) await loadOverview();
    if (view === "services" && (force || !state.services.length)) await loadServices();
    if (view === "addons" && (force || !state.addons.length)) await loadAddons();
    if (view === "configuration" && (force || !state.settings)) await loadSettings();
    if (view === "security") {
      if (force || !state.security) await loadSecurity();
      else renderSecurity();
    }
    if (view === "backups" && (force || !state.backups.length)) await loadBackups();
    if (view === "diagnostics" && force) await runDiagnostics();
    if (view === "audit" && (force || !state.audit.length)) await loadAudit();
  } catch (error) {
    reportError(error, `Could not load ${view}`);
  }
}

function activateView(view, updateHash = true) {
  if (!viewMeta[view]) view = "overview";
  state.view = view;
  const [kicker, title, subtitle] = viewMeta[view];
  document.getElementById("view-kicker").textContent = kicker;
  document.getElementById("view-title").textContent = title;
  document.getElementById("view-subtitle").textContent = subtitle;
  document.querySelectorAll("[data-view]").forEach((section) => {
    const active = section.dataset.view === view;
    section.hidden = !active;
    section.classList.toggle("is-active", active);
  });
  document.querySelectorAll("[data-nav]").forEach((item) => {
    const active = item.dataset.nav === view;
    item.classList.toggle("is-active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  if (updateHash) history.replaceState(null, "", `#${view}`);
  document.getElementById("mobile-nav").hidden = true;
  document.getElementById("mobile-menu").setAttribute("aria-expanded", "false");
  if (updateHash) document.getElementById("main-content").focus({ preventScroll: true });
  loadView(view);
}

async function fetchImpact(operation, target = "") {
  const query = new URLSearchParams({ operation });
  if (target) query.set("target", target);
  return api(`/api/impact?${query.toString()}`);
}

async function confirmImpact(operation, target = "", options = {}) {
  const impact = await fetchImpact(operation, target);
  const dialog = document.getElementById("impact-dialog");
  const field = document.getElementById("impact-confirm-field");
  const input = document.getElementById("impact-confirm-input");
  const unprotectedField = document.getElementById("impact-unprotected-field");
  const unprotectedInput = document.getElementById("impact-unprotected-input");
  const submit = document.getElementById("impact-submit");
  const requiresUnprotectedDownloads =
    options.requireUnprotectedDownloads === true;
  document.getElementById("impact-title").textContent = impact.title;
  document.getElementById("impact-consequences").innerHTML =
    (impact.consequences || []).map((item) => `<li>${escapeHTML(item)}</li>`).join("");
  field.hidden = !impact.highImpact;
  unprotectedField.hidden = !requiresUnprotectedDownloads;
  input.value = "";
  unprotectedInput.checked = false;
  input.dataset.expected = impact.confirmation;
  document.getElementById("impact-confirm-label").textContent = impact.confirmation;
  const updateSubmitState = () => {
    const typedConfirmationValid =
      !impact.highImpact || input.value === impact.confirmation;
    const exposureAcknowledged =
      !requiresUnprotectedDownloads || unprotectedInput.checked;
    submit.disabled = !typedConfirmationValid || !exposureAcknowledged;
  };
  input.addEventListener("input", updateSubmitState);
  unprotectedInput.addEventListener("change", updateSubmitState);
  updateSubmitState();
  dialog.returnValue = "";
  dialog.showModal();
  if (impact.highImpact) input.focus();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const accepted = dialog.returnValue === "confirm" &&
        (!impact.highImpact || input.value === impact.confirmation) &&
        (!requiresUnprotectedDownloads || unprotectedInput.checked);
      const decision = accepted ? {
        confirmation: impact.confirmation,
        confirmUnprotectedDownloads:
          requiresUnprotectedDownloads && unprotectedInput.checked,
      } : null;
      input.removeEventListener("input", updateSubmitState);
      unprotectedInput.removeEventListener("change", updateSubmitState);
      input.value = "";
      unprotectedInput.checked = false;
      resolve(decision);
    }, { once: true });
  });
}

function requestPassphrase(mode) {
  const dialog = document.getElementById("backup-dialog");
  const passphrase = document.getElementById("backup-passphrase");
  const confirmation = document.getElementById("backup-passphrase-confirm");
  const confirmRow = document.getElementById("backup-confirm-row");
  const relocationRow = document.getElementById("backup-relocation-row");
  const relocateRoots = document.getElementById("backup-relocate-roots");
  const error = document.getElementById("backup-field-error");
  const creating = mode === "create";
  document.getElementById("backup-dialog-title").textContent =
    creating ? "Backup passphrase" : "Restore passphrase";
  document.getElementById("backup-dialog-copy").textContent = creating
    ? "Use at least 12 characters. SDBX never stores this passphrase."
    : "Enter the archive passphrase. The verified target control plane is always preserved.";
  confirmRow.hidden = !creating;
  relocationRow.hidden = creating;
  relocateRoots.checked = false;
  passphrase.value = "";
  confirmation.value = "";
  passphrase.dataset.mode = mode;
  error.textContent = "";
  dialog.returnValue = "";
  dialog.showModal();
  passphrase.focus();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const value = dialog.returnValue === "confirm" ? passphrase.value : "";
      const relocateManagedRoots = !creating && relocateRoots.checked;
      passphrase.value = "";
      confirmation.value = "";
      relocateRoots.checked = false;
      resolve({ passphrase: value, relocateManagedRoots });
    }, { once: true });
  });
}

async function mutateStack(action) {
  const decision = await confirmImpact(`stack.${action}`);
  if (!decision) return;
  await api(`/api/actions/${action}`, {
    method: "POST",
    headers: { "X-SDBX-Confirm": decision.confirmation },
  });
  toast(`Stack ${action} requested`, "Service status will refresh now.");
  await Promise.all([loadOverview(), loadServices()]);
}

async function mutateAddon(name, action) {
  const decision = await confirmImpact(`addon.${action}`, name);
  if (!decision) return;
  await api(`/api/addons/${encodeURIComponent(name)}/${action}`, {
    method: "POST",
    headers: { "X-SDBX-Confirm": decision.confirmation },
  });
  toast(`Addon ${action}d`, name);
  await Promise.all([loadAddons(), loadOverview()]);
}

async function mutateSetting(key) {
  const input = Array.from(document.querySelectorAll("[data-setting-input]"))
    .find((element) => element.dataset.settingInput === key);
  const value = settingValue(input);
  const requiresUnprotectedDownloads =
    key === "vpn_enabled" && String(value).toLowerCase() === "false";
  const decision = await confirmImpact("setting.update", key, {
    requireUnprotectedDownloads: requiresUnprotectedDownloads,
  });
  if (!decision) return;
  await api(`/api/config/${encodeURIComponent(key)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-SDBX-Confirm": decision.confirmation,
    },
    body: JSON.stringify({
      value,
      confirmUnprotectedDownloads: decision.confirmUnprotectedDownloads,
    }),
  });
  toast("Configuration updated", key);
  await Promise.all([loadSettings(), loadOverview(), loadSecurity()]);
}

async function createBackup() {
  const decision = await confirmImpact("backup.create");
  if (!decision) return;
  const { passphrase } = await requestPassphrase("create");
  if (!passphrase) return;
  try {
    await api("/api/actions/backup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SDBX-Confirm": decision.confirmation,
      },
      body: JSON.stringify({ passphrase }),
    });
  } finally {
    document.getElementById("backup-passphrase").value = "";
  }
  toast("Encrypted backup created");
  await Promise.all([loadBackups(), loadOverview()]);
}

async function mutateBackup(name, action) {
  const decision = await confirmImpact(`backup.${action}`, name);
  if (!decision) return;
  let body;
  if (action === "restore") {
    const { passphrase, relocateManagedRoots } = await requestPassphrase("restore");
    if (!passphrase) return;
    body = JSON.stringify({ passphrase, relocateManagedRoots });
  }
  await api(`/api/backups/${encodeURIComponent(name)}/${action}`, {
    method: "POST",
    headers: {
      "X-SDBX-Confirm": decision.confirmation,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body } : {}),
  });
  toast(action === "restore" ? "Backup restored" : "Backup deleted", name);
  await Promise.all([loadBackups(), loadOverview(), loadSecurity()]);
}

function buildMobileNav() {
  const root = document.getElementById("mobile-nav");
  root.innerHTML = Array.from(document.querySelectorAll(".primary-nav .nav-item"))
    .map((button) => `
      <button class="nav-item ${button.dataset.nav === state.view ? "is-active" : ""}" data-nav="${button.dataset.nav}">
        <span class="nav-index">${escapeHTML(button.querySelector(".nav-index").textContent)}</span>
        <span>${escapeHTML(button.lastElementChild.textContent)}</span>
      </button>`).join("");
}

document.addEventListener("input", (event) => {
  if (event.target.id === "service-filter") {
    state.serviceFilter = event.target.value;
    renderServices();
  }
  if (event.target.id === "addon-filter") {
    state.addonFilter = event.target.value;
    renderAddons();
  }
});

document.getElementById("backup-submit").addEventListener("click", (event) => {
  const passphrase = document.getElementById("backup-passphrase");
  const confirmation = document.getElementById("backup-passphrase-confirm");
  const error = document.getElementById("backup-field-error");
  const creating = passphrase.dataset.mode === "create";
  if (!passphrase.value || (creating && passphrase.value.length < 12)) {
    event.preventDefault();
    error.textContent = creating ? "Use at least 12 characters." : "Enter the archive passphrase.";
    passphrase.focus();
    return;
  }
  if (creating && passphrase.value !== confirmation.value) {
    event.preventDefault();
    error.textContent = "Passphrases do not match.";
    confirmation.focus();
  }
});

document.addEventListener("click", async (event) => {
  const target = event.target.closest("button, a");
  if (!target) return;
  try {
    if (target.dataset.nav) {
      event.preventDefault();
      activateView(target.dataset.nav);
      return;
    }
    if (target.dataset.stack) await mutateStack(target.dataset.stack);
    if (target.dataset.serviceLog) {
      activateView("services");
      document.getElementById("log-service").value = target.dataset.serviceLog;
      await loadLogs();
    }
    if (target.dataset.addonAction) {
      await mutateAddon(target.dataset.addonName, target.dataset.addonAction);
    }
    if (target.dataset.settingSave) await mutateSetting(target.dataset.settingSave);
    if (target.dataset.backupAction) {
      await mutateBackup(target.dataset.backupName, target.dataset.backupAction);
    }
  } catch (error) {
    reportError(error);
  }
});

document.querySelectorAll("[data-service-status]").forEach((button) => {
  button.addEventListener("click", () => {
    state.serviceStatus = button.dataset.serviceStatus;
    document.querySelectorAll("[data-service-status]").forEach((item) =>
      item.classList.toggle("is-active", item === button));
    renderServices();
  });
});

document.querySelectorAll("[data-addon-status]").forEach((button) => {
  button.addEventListener("click", () => {
    state.addonStatus = button.dataset.addonStatus;
    document.querySelectorAll("[data-addon-status]").forEach((item) =>
      item.classList.toggle("is-active", item === button));
    renderAddons();
  });
});

document.getElementById("load-logs").addEventListener("click", () =>
  loadLogs().catch((error) => reportError(error, "Could not load logs")));

document.getElementById("toggle-live-logs").addEventListener("click", (event) => {
  state.liveLogs = !state.liveLogs;
  event.currentTarget.setAttribute("aria-pressed", String(state.liveLogs));
  event.currentTarget.textContent = state.liveLogs ? "Stop following" : "Follow";
  state.logFailures = 0;
  scheduleLogs();
  document.getElementById("log-meta").textContent =
    state.liveLogs ? "Follow mode on; reconnects automatically." : "Follow mode is off.";
});

document.getElementById("create-backup").addEventListener("click", () =>
  createBackup().catch((error) => reportError(error, "Could not create backup")));
document.getElementById("run-diagnostics").addEventListener("click", () =>
  runDiagnostics().catch((error) => reportError(error, "Diagnostics failed")));
document.getElementById("refresh-audit").addEventListener("click", () =>
  loadAudit().catch((error) => reportError(error, "Could not load audit history")));
document.getElementById("refresh-view").addEventListener("click", () =>
  loadView(state.view, true));
document.getElementById("retry-connection").addEventListener("click", () =>
  loadView(state.view, true));

document.getElementById("mobile-menu").addEventListener("click", (event) => {
  buildMobileNav();
  const nav = document.getElementById("mobile-nav");
  nav.hidden = !nav.hidden;
  event.currentTarget.setAttribute("aria-expanded", String(!nav.hidden));
  if (!nav.hidden) nav.querySelector("[data-nav]")?.focus();
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  const nav = document.getElementById("mobile-nav");
  if (nav.hidden) return;
  nav.hidden = true;
  const menu = document.getElementById("mobile-menu");
  menu.setAttribute("aria-expanded", "false");
  menu.focus();
});

window.addEventListener("hashchange", () => {
  const supplied = consumeFragmentToken();
  if (supplied) {
    token = supplied;
    showConsole();
    setConnection(false);
    activateView("overview", true);
    return;
  }
  activateView(location.hash.slice(1), false);
});
window.addEventListener("offline", () => setConnection(false));
window.addEventListener("online", () => loadView(state.view, true));
window.addEventListener("beforeunload", () => window.clearTimeout(state.logTimer));

// Remote installations are authorized by Authelia at Traefik and therefore
// do not carry the local fragment token. Start the same application flow in
// both modes; a direct unauthenticated local request still receives the API's
// fail-closed invalid_token response and falls back to the access gate.
setConnection(false);
activateView(location.hash.slice(1) || "overview", false);
