const state = {
  config: null,
  status: null,
  logsTimer: null,
  statusTimer: null,
  lang: null,
  lastPresets: [],
};

const translations = {
  fa: {
    hero_eyebrow: "Aether / Termux / داشبورد محلی",
    hero_title: "داشبورد وب Aether برای Termux",
    hero_lead: "بدون نیاز به حفظ کردن همه فلگ‌ها، از داخل مرورگر Aether را نصب، اجرا، متوقف و پایش کن.",
    lang_label: "زبان",
    vpn_title: "نکته مهم درباره VPN",
    vpn_body: "برای اجرای واقعی Aether بهتر است VPN سیستم خاموش باشد. برای دانلود یا آپدیت، اگر لازم شد می‌توانی موقتاً VPN را روشن کنی.",
    presets_title: "پریست‌های آماده",
    presets_desc: "برای شروع سریع، یکی از این پروفایل‌ها را انتخاب کن.",
    config_title: "تنظیمات اجرا",
    config_desc: "تنظیمات ذخیره می‌شوند و برای دفعات بعدی باقی می‌مانند.",
    preview_title: "دستور نهایی",
    preview_desc: "همان چیزی که داشبورد برای اجرای Aether استفاده می‌کند.",
    action_title: "خروجی آخرین عملیات",
    action_desc: "نتیجه‌ی نصب، آپدیت، تست پراکسی، و خطاهای خلاصه‌شده اینجا نمایش داده می‌شود.",
    logs_title: "لاگ زنده",
    logs_desc: "خروجی مستقیم خود Aether. هر چند ثانیه رفرش می‌شود.",
    guide_title: "راهنمای سریع",
    guide_desc: "چک‌لیست شروع، تنظیم پراکسی، و عیب‌یابی.",
    guide_quick_title: "شروع در ۳۰ ثانیه",
    guide_udp_title: "اگر UDP یا QUIC بسته بود",
    guide_tls_title: "اگر TLS ClientHello بسته می‌شود",
    guide_browser_title: "تنظیم پراکسی مرورگر",
    guide_lan_title: "دسترسی از لپ‌تاپ یا دستگاه دیگر",
    field_bind: "Bind address",
    field_protocol: "Protocol",
    field_scan_mode: "Scan mode",
    field_ip_mode: "IP mode",
    field_quick_reconnect: "Quick reconnect",
    field_noise: "Noise profile",
    field_verbose: "Verbose logs",
    field_peer: "Peer override",
    field_wg_peer: "WG peer override",
    label_proxy: "Proxy",
    label_pid: "PID",
    label_uptime: "Uptime",
    label_panel: "Panel",
    label_binary: "Aether binary",
    label_log_file: "Log file",
    auto_refresh: "رفرش خودکار",
    btn_install: "نصب Aether",
    btn_start: "اجرای Aether",
    btn_stop: "توقف",
    btn_test: "تست پراکسی",
    btn_save: "ذخیره تنظیمات",
    btn_restart: "ری‌استارت",
    btn_update_core: "آپدیت هسته",
    btn_update_panel: "آپدیت پنل",
    btn_uninstall: "حذف",
    btn_refresh_logs: "رفرش لاگ",
    btn_clear: "پاک کردن",
    status_idle: "آماده",
    status_running: "در حال اجرا",
    status_stopped: "متوقف",
    version_prefix: "نسخه:",
    installed_text: "نصب شده",
    not_installed: "نصب نشده",
    no_logs: "هنوز لاگی وجود ندارد.",
    no_action_yet: "هنوز عملیاتی اجرا نشده است.",
    save_success: "تنظیمات ذخیره شد.",
    install_success: "Aether نصب شد یا لاگ نصب نمایش داده شد.",
    core_update_success: "آپدیت هسته Aether انجام شد یا آغاز شد.",
    panel_update_success: "آپدیت پنل شروع شد؛ اگر پنل برای چند ثانیه قطع شد طبیعی است.",
    uninstall_success: "Aether حذف شد.",
    start_success: "Aether اجرا شد.",
    stop_success: "Aether متوقف شد.",
    restart_success: "Aether ری‌استارت شد.",
    test_success: "تست پراکسی انجام شد.",
    confirm_uninstall: "Aether uninstall شود؟",
    op_completed: "عملیات انجام شد",
    op_failed: "خطا",
    action_ok_prefix: "✅",
    action_err_prefix: "❌",
    quick_list_html: "<li>روی <strong>نصب Aether</strong> بزن.</li><li>پریست <strong>ایران / حالت پیشنهادی</strong> را انتخاب کن.</li><li>روی <strong>ذخیره تنظیمات</strong> و بعد <strong>اجرای Aether</strong> بزن.</li><li>پراکسی مرورگر را روی <code>127.0.0.1:1819</code> با نوع <code>SOCKS5</code> تنظیم کن.</li><li>با <strong>تست پراکسی</strong> مطمئن شو ترافیک عبور می‌کند.</li>",
    udp_body_html: "پریست <strong>UDP بسته است</strong> را انتخاب کن. این حالت از MASQUE روی h2/TCP استفاده می‌کند.",
    tls_body_html: "پریست <strong>DPI سخت‌گیر</strong> را امتحان کن یا در بخش MASQUE گزینه <strong>Fragment TLS ClientHello</strong> را برای h2 روشن کن.",
    browser_list_html: "<li>Host: <code>127.0.0.1</code></li><li>Port: <code>1819</code></li><li>Type: <code>SOCKS5</code></li><li>اگر ممکن بود، DNS هم از داخل پراکسی عبور کند.</li>",
    lan_body_html: "داشبورد را با <code>aether-web --host 0.0.0.0 --port 8787</code> اجرا کن و فقط روی شبکه محلی مطمئن از آن استفاده کن.",
  },
  en: {
    hero_eyebrow: "Aether / Termux / Local Dashboard",
    hero_title: "Aether Web Dashboard for Termux",
    hero_lead: "Install, run, stop, and monitor Aether from your browser without memorizing every CLI flag.",
    lang_label: "Language",
    vpn_title: "Important VPN note",
    vpn_body: "For real Aether usage, it is better to keep your system VPN off. For downloads or updates, you can temporarily enable a VPN if needed.",
    presets_title: "Ready-made presets",
    presets_desc: "Pick one of these profiles for a fast start.",
    config_title: "Run settings",
    config_desc: "Your settings are saved and reused next time.",
    preview_title: "Final command",
    preview_desc: "This is the exact command the dashboard will use to launch Aether.",
    action_title: "Latest action output",
    action_desc: "Install, update, proxy test, and summarized error output is shown here.",
    logs_title: "Live logs",
    logs_desc: "Direct Aether output. Refreshed every few seconds.",
    guide_title: "Quick guide",
    guide_desc: "Startup checklist, proxy setup, and troubleshooting.",
    guide_quick_title: "Start in 30 seconds",
    guide_udp_title: "If UDP or QUIC is blocked",
    guide_tls_title: "If TLS ClientHello gets blocked",
    guide_browser_title: "Browser proxy setup",
    guide_lan_title: "Access from a laptop or another device",
    field_bind: "Bind address",
    field_protocol: "Protocol",
    field_scan_mode: "Scan mode",
    field_ip_mode: "IP mode",
    field_quick_reconnect: "Quick reconnect",
    field_noise: "Noise profile",
    field_verbose: "Verbose logs",
    field_peer: "Peer override",
    field_wg_peer: "WG peer override",
    label_proxy: "Proxy",
    label_pid: "PID",
    label_uptime: "Uptime",
    label_panel: "Panel",
    label_binary: "Aether binary",
    label_log_file: "Log file",
    auto_refresh: "Auto refresh",
    btn_install: "Install Aether",
    btn_start: "Start Aether",
    btn_stop: "Stop",
    btn_test: "Proxy Test",
    btn_save: "Save settings",
    btn_restart: "Restart",
    btn_update_core: "Update Core",
    btn_update_panel: "Update Panel",
    btn_uninstall: "Uninstall",
    btn_refresh_logs: "Refresh logs",
    btn_clear: "Clear",
    status_idle: "Idle",
    status_running: "Running",
    status_stopped: "Stopped",
    version_prefix: "Version:",
    installed_text: "installed",
    not_installed: "not installed",
    no_logs: "No logs yet.",
    no_action_yet: "No action has been run yet.",
    save_success: "Settings saved.",
    install_success: "Aether was installed or the installer log was shown.",
    core_update_success: "Aether core update completed or started.",
    panel_update_success: "Panel update started. A short disconnect is normal while it restarts.",
    uninstall_success: "Aether was removed.",
    start_success: "Aether started.",
    stop_success: "Aether stopped.",
    restart_success: "Aether restarted.",
    test_success: "Proxy test completed.",
    confirm_uninstall: "Uninstall Aether?",
    op_completed: "Operation completed",
    op_failed: "Error",
    action_ok_prefix: "✅",
    action_err_prefix: "❌",
    quick_list_html: "<li>Click <strong>Install Aether</strong>.</li><li>Choose the <strong>Iran / Recommended</strong> preset.</li><li>Click <strong>Save settings</strong> and then <strong>Start Aether</strong>.</li><li>Set your browser proxy to <code>127.0.0.1:1819</code> using <code>SOCKS5</code>.</li><li>Use <strong>Proxy Test</strong> to verify traffic really passes.</li>",
    udp_body_html: "Choose the <strong>UDP Blocked</strong> preset. It runs MASQUE over h2/TCP.",
    tls_body_html: "Try the <strong>Strict DPI</strong> preset, or enable <strong>Fragment TLS ClientHello</strong> for h2 in the MASQUE section.",
    browser_list_html: "<li>Host: <code>127.0.0.1</code></li><li>Port: <code>1819</code></li><li>Type: <code>SOCKS5</code></li><li>If possible, route DNS through the proxy too.</li>",
    lan_body_html: "Run the dashboard with <code>aether-web --host 0.0.0.0 --port 8787</code> and only use this mode on a trusted local network.",
  },
};

const noiseOptions = {
  masque: ["firewall", "gfw", "off"],
  wg: ["balanced", "aggressive", "light", "off"],
  gool: ["balanced", "aggressive", "light", "off"],
};

const $ = (id) => document.getElementById(id);

function preferredLanguage() {
  const saved = localStorage.getItem("aether-web-lang");
  if (saved === "fa" || saved === "en") return saved;
  const browser = (navigator.language || "").toLowerCase();
  return browser.startsWith("fa") ? "fa" : "en";
}

function t(key) {
  const lang = state.lang || preferredLanguage();
  return translations[lang]?.[key] ?? translations.fa[key] ?? key;
}

function applyTranslations() {
  const lang = state.lang || preferredLanguage();
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("lang-en", lang === "en");
  $("langSwitcher").value = lang;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });

  $("installBtn").textContent = t("btn_install");
  $("startBtn").textContent = t("btn_start");
  $("stopBtn").textContent = t("btn_stop");
  $("testBtn").textContent = t("btn_test");
  $("saveBtn").textContent = t("btn_save");
  $("restartBtn").textContent = t("btn_restart");
  $("updateBtn").textContent = t("btn_update_core");
  $("updatePanelBtn").textContent = t("btn_update_panel");
  $("uninstallBtn").textContent = t("btn_uninstall");
  $("refreshLogsBtn").textContent = t("btn_refresh_logs");
  $("clearActionOutputBtn").textContent = t("btn_clear");

  $("guideQuickList").innerHTML = t("quick_list_html");
  $("guideUdpBody").innerHTML = t("udp_body_html");
  $("guideTlsBody").innerHTML = t("tls_body_html");
  $("guideBrowserList").innerHTML = t("browser_list_html");
  $("guideLanBody").innerHTML = t("lan_body_html");

  if ($("actionOutputBox").dataset.empty === "1") {
    setActionOutput(t("no_action_yet"));
  }
  if ($("logsBox").dataset.empty === "1") {
    $("logsBox").textContent = t("no_logs");
  }
}

function setLanguage(lang) {
  state.lang = lang === "en" ? "en" : "fa";
  localStorage.setItem("aether-web-lang", state.lang);
  applyTranslations();
  renderPresets(state.status?.presets || state.lastPresets || []);
  if (state.status) refreshStatus().catch(() => {});
}

function showToast(message, kind = "info") {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  el.style.borderColor = kind === "error" ? "rgba(255, 107, 136, 0.4)" : "rgba(120, 177, 255, 0.18)";
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add("hidden"), 4000);
}

function summarizeText(text, fallback = t("op_failed")) {
  const raw = String(text || "").trim();
  if (!raw) return fallback;

  const lines = raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    const lowered = line.toLowerCase();
    if (lowered.startsWith("usage:")) continue;
    if (line.length <= 180) return line;
    return `${line.slice(0, 177)}...`;
  }

  return lines[0] || fallback;
}

function setActionOutput(title, text = "") {
  const content = String(text || "").trim();
  $("actionOutputBox").dataset.empty = content || title !== t("no_action_yet") ? "0" : "1";
  $("actionOutputBox").textContent = content ? `${title}\n\n${content}` : title;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.ok === false) {
    const fullOutput = data.output || data.message || `Request failed: ${response.status}`;
    const err = new Error(summarizeText(fullOutput, `Request failed: ${response.status}`));
    err.fullOutput = fullOutput;
    err.payload = data;
    throw err;
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
  showToast(`${t("action_ok_prefix")} ${presetText(preset, "label")}`);
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

function presetText(preset, key) {
  if (state.lang === "en") {
    return preset[`${key}_en`] || preset[`${key}_fa`] || preset[key] || "";
  }
  return preset[`${key}_fa`] || preset[`${key}_en`] || preset[key] || "";
}

function renderPresets(presets) {
  state.lastPresets = presets;
  const container = $("presets");
  container.innerHTML = "";
  presets.forEach((preset) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card";
    card.innerHTML = `<strong>${presetText(preset, "label")}</strong><p>${presetText(preset, "description")}</p>`;
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
  $("binaryVersion").textContent = `${t("version_prefix")} ${status.binary.version || (status.binary.exists ? t("installed_text") : t("not_installed"))}`;
  $("binaryPathView").textContent = status.binary.path;
  $("logPathView").textContent = status.log_file;
  $("commandPreview").textContent = status.command_preview || "--";
  $("serverUrls").textContent = (status.urls || []).join("  |  ") || "--";

  const badge = $("runningBadge");
  badge.className = "badge";
  if (status.running) {
    badge.classList.add("running");
    badge.textContent = t("status_running");
  } else if (status.last_exit_note) {
    badge.classList.add("error");
    badge.textContent = `${t("status_stopped")} (${status.last_exit_note})`;
  } else {
    badge.classList.add("idle");
    badge.textContent = t("status_idle");
  }

  renderDocs(data.status.docs || status.docs || []);
}

async function refreshLogs(force = false) {
  if (!force && !$("autoRefreshLogs").checked) return;
  const data = await api("/api/logs?tail=250");
  const text = data.log || t("no_logs");
  $("logsBox").dataset.empty = data.log ? "0" : "1";
  $("logsBox").textContent = text;
  $("logsBox").scrollTop = $("logsBox").scrollHeight;
}

async function loadConfig() {
  const data = await api("/api/config");
  state.config = data.config;
  state.lastPresets = data.presets || [];
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
  if (showMessage) showToast(t("save_success"));
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
      setActionOutput(`${t("action_ok_prefix")} ${successMessage || t("op_completed")}`, result.output);
    } else if (result?.message) {
      setActionOutput(`${t("action_ok_prefix")} ${successMessage || t("op_completed")}`, result.message);
    }
    await refreshStatus();
    await refreshLogs();
    return result;
  } catch (error) {
    setActionOutput(`${t("action_err_prefix")} ${error.message || t("op_failed")}`, error.fullOutput || error.message || t("op_failed"));
    showToast(error.message || t("op_failed"), "error");
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
  state.lang = preferredLanguage();
  bindFormUpdates();
  $("langSwitcher").addEventListener("change", (event) => setLanguage(event.target.value));
  applyTranslations();
  setActionOutput(t("no_action_yet"));
  $("logsBox").dataset.empty = "1";
  $("logsBox").textContent = t("no_logs");

  await loadConfig();
  await refreshStatus();
  await refreshLogs();
  updatePreviewFromForm();

  $("saveBtn").addEventListener("click", () => handleAction($("saveBtn"), () => saveConfig(), t("save_success")));
  $("installBtn").addEventListener("click", () => handleAction($("installBtn"), () => api("/api/install", { method: "POST", body: JSON.stringify({}) }), t("install_success")));
  $("updateBtn").addEventListener("click", () => handleAction($("updateBtn"), () => api("/api/update", { method: "POST", body: JSON.stringify({}) }), t("core_update_success")));
  $("updatePanelBtn").addEventListener("click", () => handleAction($("updatePanelBtn"), () => api("/api/update-panel", { method: "POST", body: JSON.stringify({}) }), t("panel_update_success")));
  $("uninstallBtn").addEventListener("click", async () => {
    if (!confirm(t("confirm_uninstall"))) return;
    await handleAction($("uninstallBtn"), () => api("/api/uninstall", { method: "POST", body: JSON.stringify({}) }), t("uninstall_success"));
  });
  $("startBtn").addEventListener("click", () => handleAction($("startBtn"), async () => {
    const config = await saveConfig(false);
    return api("/api/start", { method: "POST", body: JSON.stringify({ config }) });
  }, t("start_success")));
  $("stopBtn").addEventListener("click", () => handleAction($("stopBtn"), () => api("/api/stop", { method: "POST", body: JSON.stringify({}) }), t("stop_success")));
  $("restartBtn").addEventListener("click", () => handleAction($("restartBtn"), async () => {
    const config = await saveConfig(false);
    return api("/api/restart", { method: "POST", body: JSON.stringify({ config }) });
  }, t("restart_success")));
  $("testBtn").addEventListener("click", () => handleAction($("testBtn"), () => api("/api/test", { method: "POST", body: JSON.stringify({}) }), t("test_success")));
  $("refreshLogsBtn").addEventListener("click", () => refreshLogs(true));
  $("clearActionOutputBtn").addEventListener("click", () => setActionOutput(t("no_action_yet")));

  state.statusTimer = setInterval(() => refreshStatus().catch((error) => showToast(error.message, "error")), 3000);
  state.logsTimer = setInterval(() => refreshLogs().catch((error) => showToast(error.message, "error")), 2500);
}

init().catch((error) => {
  const title = `${t("action_err_prefix")} ${t("op_failed")}`;
  setActionOutput(title, error.fullOutput || error.message || String(error));
  $("logsBox").textContent = error.message || String(error);
  showToast(error.message || t("op_failed"), "error");
});
