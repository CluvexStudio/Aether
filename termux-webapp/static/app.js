const state = {
  config: null,
  status: null,
  logsTimer: null,
  statusTimer: null,
};

const noiseOptions = {
  masque: ["firewall", "gfw", "off"],
  wg: ["balanced", "aggressive", "light", "off"],
  gool: ["balanced", "aggressive", "light", "off"],
};

const $ = (id) => document.getElementById(id);

function showToast(message, kind = "info") {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  el.style.borderColor = kind === "error" ? "rgba(255, 107, 136, 0.4)" : "rgba(120, 177, 255, 0.18)";
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add("hidden"), 4000);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    throw new Error(data.message || data.output || `Request failed: ${response.status}`);
  }
  return data;
}

function populateNoiseOptions(protocol, selected = "") {
  const select = $("noiseProfile");
  select.innerHTML = "";
  const options = noiseOptions[protocol] || noiseOptions.masque;
  options.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    if (value === selected) option.selected = true;
    select.appendChild(option);
  });
}

function currentNoiseDefault(protocol) {
  return protocol === "masque" ? "firewall" : "balanced";
}

function fillConfig(cfg) {
  state.config = cfg;
  $("bindAddress").value = cfg.bind_address || "127.0.0.1:1819";
  $("protocol").value = cfg.protocol || "masque";
  $("scanMode").value = cfg.scan_mode || "balanced";
  $("ipMode").value = cfg.ip_mode || "v4";
  $("quickReconnect").value = cfg.quick_reconnect || "ask";
  populateNoiseOptions(cfg.protocol, cfg.noise_profile || currentNoiseDefault(cfg.protocol));
  $("verbose").checked = !!cfg.verbose;
  $("peer").value = cfg.peer || "";
  $("wgPeer").value = cfg.wg_peer || "";

  $("masqueTransport").value = cfg.masque?.transport || "h3";
  $("h2Peer").value = cfg.masque?.h2_peer || "";
  $("ech").value = cfg.masque?.ech || "";
  $("fragment").checked = !!cfg.masque?.fragment;
  $("fragmentSize").value = cfg.masque?.fragment_size || "16-32";
  $("fragmentDelay").value = cfg.masque?.fragment_delay || "2-10";
  $("validateSecs").value = cfg.masque?.validate_secs || "10";
  $("masqueReconnectSecs").value = cfg.masque?.reconnect_secs || "2";
  $("masqueNoDataCheck").checked = !!cfg.masque?.no_data_check;

  $("keepalive").value = cfg.wireguard?.keepalive || "5";
  $("wgReconnectSecs").value = cfg.wireguard?.reconnect_secs || "2";
  $("wgNoDataCheck").checked = !!cfg.wireguard?.no_data_check;
  $("noProfileRetry").checked = !!cfg.wireguard?.no_profile_retry;

  $("binaryPath").value = cfg.advanced?.binary_path || "";
  $("baseConfig").value = cfg.config_paths?.base || "";
  $("wgConfig").value = cfg.config_paths?.wg || "";
  $("masqueConfig").value = cfg.config_paths?.masque || "";
  $("tlsGroups").value = cfg.advanced?.tls_groups || "";
  $("extraArgs").value = cfg.advanced?.extra_args || "";
  $("envBlock").value = cfg.advanced?.env_block || "";

  syncVisibility();
}

function gatherConfig() {
  const protocol = $("protocol").value;
  return {
    bind_address: $("bindAddress").value.trim(),
    protocol,
    scan_mode: $("scanMode").value,
    ip_mode: $("ipMode").value,
    quick_reconnect: $("quickReconnect").value,
    noise_profile: $("noiseProfile").value,
    verbose: $("verbose").checked,
    peer: $("peer").value.trim(),
    wg_peer: $("wgPeer").value.trim(),
    masque: {
      transport: $("masqueTransport").value,
      h2_peer: $("h2Peer").value.trim(),
      ech: $("ech").value.trim(),
      fragment: $("fragment").checked,
      fragment_size: $("fragmentSize").value.trim(),
      fragment_delay: $("fragmentDelay").value.trim(),
      validate_secs: $("validateSecs").value.trim(),
      reconnect_secs: $("masqueReconnectSecs").value.trim(),
      no_data_check: $("masqueNoDataCheck").checked,
    },
    wireguard: {
      keepalive: $("keepalive").value.trim(),
      reconnect_secs: $("wgReconnectSecs").value.trim(),
      no_data_check: $("wgNoDataCheck").checked,
      no_profile_retry: $("noProfileRetry").checked,
    },
    config_paths: {
      base: $("baseConfig").value.trim(),
      wg: $("wgConfig").value.trim(),
      masque: $("masqueConfig").value.trim(),
    },
    advanced: {
      binary_path: $("binaryPath").value.trim(),
      tls_groups: $("tlsGroups").value.trim(),
      extra_args: $("extraArgs").value.trim(),
      env_block: $("envBlock").value,
    },
  };
}

function cloneValue(value) {
  return JSON.parse(JSON.stringify(value ?? {}));
}

function applyPreset(preset) {
  const merged = cloneValue(state.config || {});
  const patch = cloneValue(preset.config || {});
  state.config = deepMerge(merged, patch);
  if (!patch.noise_profile) {
    state.config.noise_profile = currentNoiseDefault(state.config.protocol);
  }
  fillConfig(state.config);
  updatePreviewFromForm();
  showToast(`پریست «${preset.label}» اعمال شد.`);
}

function deepMerge(target, patch) {
  const output = cloneValue(target || {});
  Object.entries(patch || {}).forEach(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      output[key] = deepMerge(output[key] || {}, value);
    } else {
      output[key] = value;
    }
  });
  return output;
}

function renderPresets(presets) {
  const container = $("presets");
  container.innerHTML = "";
  presets.forEach((preset) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card";
    card.innerHTML = `<strong>${preset.label}</strong><p>${preset.description}</p>`;
    card.addEventListener("click", () => applyPreset(preset));
    container.appendChild(card);
  });
}

function renderDocs(docs) {
  const container = $("docsLinks");
  container.innerHTML = "";
  (docs || []).forEach((doc) => {
    const link = document.createElement("a");
    link.href = doc.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = doc.name;
    container.appendChild(link);
  });
}

function syncVisibility() {
  const protocol = $("protocol").value;
  $("masqueFields").style.display = protocol === "masque" ? "block" : "none";
  $("wgFields").style.display = protocol === "wg" || protocol === "gool" ? "block" : "none";

  const current = $("noiseProfile").value;
  populateNoiseOptions(protocol, current || currentNoiseDefault(protocol));
}

async function refreshStatus() {
  const data = await api("/api/status");
  state.status = data.status;
  const status = data.status;

  $("proxyAddr").textContent = status.config.bind_address;
  $("pidValue").textContent = status.pid || "--";
  $("uptimeValue").textContent = status.running ? status.uptime_human : "--";
  $("binaryVersion").textContent = status.binary.version || (status.binary.exists ? "installed" : "not installed");
  $("binaryPathView").textContent = status.binary.path;
  $("logPathView").textContent = status.log_file;
  $("commandPreview").textContent = status.command_preview || "--";
  $("serverUrls").textContent = (status.urls || []).join("  |  ") || "--";

  const badge = $("runningBadge");
  badge.className = "badge";
  if (status.running) {
    badge.classList.add("running");
    badge.textContent = "Running";
  } else if (status.last_exit_note) {
    badge.classList.add("error");
    badge.textContent = `Stopped (${status.last_exit_note})`;
  } else {
    badge.classList.add("idle");
    badge.textContent = "Idle";
  }

  renderDocs(data.status.docs || status.docs || []);
}

async function refreshLogs(force = false) {
  if (!force && !$("autoRefreshLogs").checked) return;
  const data = await api("/api/logs?tail=250");
  $("logsBox").textContent = data.log || "No logs yet.";
  $("logsBox").scrollTop = $("logsBox").scrollHeight;
}

async function loadConfig() {
  const data = await api("/api/config");
  state.config = data.config;
  fillConfig(data.config);
  renderPresets(data.presets || []);
  renderDocs(data.docs || []);
  if (data.plan?.command_preview) {
    $("commandPreview").textContent = data.plan.command_preview;
  }
}

async function saveConfig(showMessage = true) {
  const config = gatherConfig();
  const data = await api("/api/config", {
    method: "POST",
    body: JSON.stringify({ config }),
  });
  state.config = data.config;
  $("commandPreview").textContent = data.plan.command_preview || "--";
  if (showMessage) showToast("تنظیمات ذخیره شد.");
  return data.config;
}

async function handleAction(button, work, successMessage) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "...";
  try {
    const result = await work();
    if (successMessage) showToast(successMessage);
    if (result?.output) {
      $("logsBox").textContent = result.output;
    }
    await refreshStatus();
    await refreshLogs();
    return result;
  } catch (error) {
    showToast(error.message || "خطا", "error");
    throw error;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function updatePreviewFromForm() {
  const config = gatherConfig();
  const env = [];
  const args = [config.advanced.binary_path || "aether"];
  args.push("--bind", config.bind_address || "127.0.0.1:1819");
  args.push(config.protocol === "wg" ? "--wg" : config.protocol === "gool" ? "--gool" : "--masque");
  if (config.quick_reconnect === "on") args.push("--quick-reconnect");
  if (config.quick_reconnect === "off") args.push("--no-quick-reconnect");
  args.push(config.ip_mode === "v6" ? "-6" : config.ip_mode === "both" ? "--dual" : "-4");
  args.push("--scan", config.scan_mode);
  if (config.noise_profile) args.push("--noize", config.noise_profile);
  if (config.peer) args.push("--peer", config.peer);
  if (config.wg_peer) args.push("--wg-peer", config.wg_peer);
  if (config.verbose) args.push("--verbose");
  if (config.config_paths.base) args.push("--config", config.config_paths.base);
  if (config.config_paths.wg) args.push("--wg-config", config.config_paths.wg);
  if (config.config_paths.masque) args.push("--masque-config", config.config_paths.masque);
  if (config.advanced.tls_groups) args.push("--tls-groups", config.advanced.tls_groups);

  if (config.protocol === "masque") {
    if (config.masque.transport === "h2") args.push("--h2");
    if (config.masque.h2_peer) args.push("--h2-peer", config.masque.h2_peer);
    if (config.masque.ech) args.push("--ech", config.masque.ech);
    if (config.masque.no_data_check) args.push("--no-data-check");
    if (config.masque.validate_secs) args.push("--validate-secs", config.masque.validate_secs);
    if (config.masque.reconnect_secs) args.push("--reconnect-secs", config.masque.reconnect_secs);
    if (config.masque.fragment && config.masque.transport === "h2") {
      args.push("--fragment");
      if (config.masque.fragment_size) args.push("--fragment-size", config.masque.fragment_size);
      if (config.masque.fragment_delay) args.push("--fragment-delay", config.masque.fragment_delay);
    }
  } else {
    if (config.wireguard.keepalive) args.push("--keepalive", config.wireguard.keepalive);
    if (config.wireguard.no_data_check) args.push("--no-data-check");
    if (config.wireguard.no_profile_retry) args.push("--no-profile-retry");
    if (config.wireguard.reconnect_secs) env.push(`AETHER_WG_RECONNECT_SECS=${config.wireguard.reconnect_secs}`);
  }

  if (config.advanced.env_block?.trim()) {
    config.advanced.env_block
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((line) => env.push(line));
  }
  if (config.advanced.extra_args?.trim()) args.push(config.advanced.extra_args.trim());

  const preview = `${env.join(" ")} ${args.join(" ")}`.trim();
  $("commandPreview").textContent = preview || "--";
}

function bindFormUpdates() {
  const ids = [
    "bindAddress", "protocol", "scanMode", "ipMode", "quickReconnect", "noiseProfile", "verbose", "peer", "wgPeer",
    "masqueTransport", "h2Peer", "ech", "fragment", "fragmentSize", "fragmentDelay", "validateSecs",
    "masqueReconnectSecs", "masqueNoDataCheck", "keepalive", "wgReconnectSecs", "wgNoDataCheck",
    "noProfileRetry", "binaryPath", "baseConfig", "wgConfig", "masqueConfig", "tlsGroups", "extraArgs", "envBlock"
  ];
  ids.forEach((id) => {
    $(id).addEventListener("input", updatePreviewFromForm);
    $(id).addEventListener("change", () => {
      if (id === "protocol") {
        const protocol = $("protocol").value;
        populateNoiseOptions(protocol, currentNoiseDefault(protocol));
        syncVisibility();
      }
      updatePreviewFromForm();
    });
  });
}

async function init() {
  bindFormUpdates();
  await loadConfig();
  await refreshStatus();
  await refreshLogs();
  updatePreviewFromForm();

  $("saveBtn").addEventListener("click", () => handleAction($("saveBtn"), () => saveConfig(), "تنظیمات ذخیره شد."));
  $("installBtn").addEventListener("click", () => handleAction($("installBtn"), () => api("/api/install", { method: "POST", body: JSON.stringify({}) }), "Aether نصب شد یا لاگ نصب نمایش داده شد."));
  $("updateBtn").addEventListener("click", () => handleAction($("updateBtn"), () => api("/api/update", { method: "POST", body: JSON.stringify({}) }), "درخواست آپدیت انجام شد."));
  $("uninstallBtn").addEventListener("click", async () => {
    if (!confirm("Aether uninstall شود؟")) return;
    await handleAction($("uninstallBtn"), () => api("/api/uninstall", { method: "POST", body: JSON.stringify({}) }), "Aether حذف شد.");
  });
  $("startBtn").addEventListener("click", () => handleAction($("startBtn"), async () => {
    const config = await saveConfig(false);
    return api("/api/start", { method: "POST", body: JSON.stringify({ config }) });
  }, "Aether اجرا شد."));
  $("stopBtn").addEventListener("click", () => handleAction($("stopBtn"), () => api("/api/stop", { method: "POST", body: JSON.stringify({}) }), "Aether متوقف شد."));
  $("restartBtn").addEventListener("click", () => handleAction($("restartBtn"), async () => {
    const config = await saveConfig(false);
    return api("/api/restart", { method: "POST", body: JSON.stringify({ config }) });
  }, "Aether ری‌استارت شد."));
  $("testBtn").addEventListener("click", () => handleAction($("testBtn"), () => api("/api/test", { method: "POST", body: JSON.stringify({}) }), "تست انجام شد. خروجی پایین نمایش داده شد."));
  $("refreshLogsBtn").addEventListener("click", () => refreshLogs(true));

  state.statusTimer = setInterval(() => refreshStatus().catch((error) => showToast(error.message, "error")), 3000);
  state.logsTimer = setInterval(() => refreshLogs().catch((error) => showToast(error.message, "error")), 2500);
}

init().catch((error) => {
  $("logsBox").textContent = error.message || String(error);
  showToast(error.message || "خطا در بارگذاری داشبورد", "error");
});
