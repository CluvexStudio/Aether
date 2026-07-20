const DEFAULT_CONFIG = {
  bind_address: "127.0.0.1:1819",
  protocol: "masque",
  scan_mode: "balanced",
  ip_mode: "v4",
  quick_reconnect: "ask",
  noise_profile: "firewall",
  verbose: true,
  peer: "",
  wg_peer: "",
  masque: {
    transport: "h3",
    h2_peer: "",
    ech: "",
    fragment: false,
    fragment_size: "16-32",
    fragment_delay: "2-10",
    validate_secs: "10",
    reconnect_secs: "2",
    no_data_check: false,
  },
  wireguard: {
    keepalive: "5",
    reconnect_secs: "2",
    no_data_check: false,
    no_profile_retry: false,
  },
  config_paths: {
    base: "",
    wg: "",
    masque: "",
  },
  advanced: {
    binary_path: "/data/data/com.termux/files/usr/bin/aether",
    tls_groups: "",
    extra_args: "",
    env_block: "",
  },
};

const state = {
  config: JSON.parse(JSON.stringify(DEFAULT_CONFIG)),
  status: null,
  logsTimer: null,
  statusTimer: null,
  healthTimer: null,
  lang: null,
  viewMode: "simple",
  lastPresets: [],
  docs: [],
  histories: [],
  backups: [],
  notifications: [],
  siteChecks: [],
  selectedCategory: "auto",
  smartBusy: false,
  menuOpen: false,
  liteMode: false,
  backendReady: false,
  proxyHealth: null,
  proxyHealthDetail: null,
  deferredPrompt: null,
  cameraStream: null,
  cameraFrame: null,
  actionText: "",
  actionTitle: "",
  rawLogs: "",
  logFilter: "all",
};

const STORAGE_KEYS = {
  lang: "aether-web-lang",
  view: "aether-web-view",
  liteConfig: "aether-web-lite-config",
  history: "aether-web-history",
  backups: "aether-web-backups",
  notifications: "aether-web-notifications",
};

const FALLBACK_PRESETS = [
  {
    id: "iran-recommended",
    label_fa: "ایران / حالت پیشنهادی",
    label_en: "Iran / Recommended",
    description_fa: "MASQUE روی h3 با نویز firewall و اسکن balanced؛ شروع امن و سریع برای بیشتر شبکه‌ها.",
    description_en: "MASQUE over h3 with firewall noise and balanced scan; a safe first choice for most networks.",
    config: { protocol: "masque", scan_mode: "balanced", ip_mode: "v4", quick_reconnect: "on", noise_profile: "firewall", masque: { transport: "h3", fragment: false } },
  },
  {
    id: "udp-blocked",
    label_fa: "UDP بسته است",
    label_en: "UDP Blocked",
    description_fa: "MASQUE روی h2/TCP؛ مناسب وقتی HTTP/3 یا QUIC وصل نمی‌شود.",
    description_en: "MASQUE over h2/TCP; use this when HTTP/3 or QUIC does not connect.",
    config: { protocol: "masque", scan_mode: "balanced", ip_mode: "v4", quick_reconnect: "on", noise_profile: "firewall", masque: { transport: "h2", fragment: false } },
  },
  {
    id: "strict-dpi",
    label_fa: "DPI سخت‌گیر",
    label_en: "Strict DPI",
    description_fa: "MASQUE روی h2 با fragmentation و نویز gfw برای شبکه‌های خیلی سخت‌گیر.",
    description_en: "MASQUE over h2 with fragmentation and gfw noise for very strict filtering.",
    config: { protocol: "masque", scan_mode: "ironclad", ip_mode: "v4", quick_reconnect: "on", noise_profile: "gfw", masque: { transport: "h2", fragment: true, fragment_size: "8-24", fragment_delay: "5-15" } },
  },
  {
    id: "wg-fast",
    label_fa: "WireGuard سریع",
    label_en: "Fast WireGuard",
    description_fa: "برای شبکه‌های کمتر سخت‌گیر یا وقتی سرعت مهم‌تر از استتار است.",
    description_en: "For less restrictive networks or when speed matters more than stealth.",
    config: { protocol: "wg", scan_mode: "balanced", ip_mode: "v4", quick_reconnect: "on", noise_profile: "balanced", wireguard: { keepalive: "5", no_profile_retry: false } },
  },
  {
    id: "gool-stability",
    label_fa: "GOOL پایدار",
    label_en: "Stable GOOL",
    description_fa: "تونل دولایه برای وقتی که WireGuard معمولی وصل می‌شود اما ناپایدار است.",
    description_en: "A nested tunnel for cases where plain WireGuard connects but is unstable.",
    config: { protocol: "gool", scan_mode: "thorough", ip_mode: "v4", quick_reconnect: "on", noise_profile: "aggressive", wireguard: { keepalive: "5", no_profile_retry: false } },
  },
];


const CATEGORY_PROFILES = [
  {
    id: "auto",
    label_fa: "هوشمند",
    label_en: "Smart Auto",
    description_fa: "با توجه به وضعیت شبکه، بهترین حالت را پیشنهاد می‌دهد.",
    description_en: "Picks a practical mode based on current network conditions.",
  },
  {
    id: "gaming",
    label_fa: "گیم",
    label_en: "Gaming",
    description_fa: "تا حد ممکن کم‌سربار و سریع؛ مناسب بازی اگر شبکه اجازه بدهد.",
    description_en: "Low-overhead and fast; good for games when the network allows it.",
  },
  {
    id: "streaming",
    label_fa: "استریم",
    label_en: "Streaming",
    description_fa: "پایداری و throughput بهتر برای ویدیو و استریم.",
    description_en: "Better stability and throughput for video and streaming.",
  },
  {
    id: "social",
    label_fa: "وب و سوشیال",
    label_en: "Web & Social",
    description_fa: "برای وب‌گردی، تلگرام وب و شبکه‌های اجتماعی؛ h2 را ترجیح می‌دهد.",
    description_en: "For browsing, Telegram Web, and social apps; prefers h2 when useful.",
  },
  {
    id: "strict",
    label_fa: "ضد DPI",
    label_en: "Anti-DPI",
    description_fa: "سخت‌گیرانه‌تر؛ h2 + fragmentation + gfw برای شبکه‌های خیلی بدقلق.",
    description_en: "Stricter mode; h2 + fragmentation + gfw for very hostile networks.",
  },
  {
    id: "stable",
    label_fa: "پایدار",
    label_en: "Stable",
    description_fa: "اگر تک‌لایه جواب نداد، GOOL / حالت پایدارتر را ترجیح می‌دهد.",
    description_en: "Prefers a more resilient path like GOOL when simpler modes fail.",
  },
];

const noiseOptions = {
  masque: ["firewall", "gfw", "off"],
  wg: ["balanced", "aggressive", "light", "off"],
  gool: ["balanced", "aggressive", "light", "off"],
};

const $ = (id) => document.getElementById(id);

const translations = {
  fa: {
    hero_eyebrow: "Aether / Termux / داشبورد محلی",
    hero_title: "داشبورد وب Aether برای Termux",
    hero_lead: "بدون نیاز به حفظ کردن فلگ‌ها، از داخل مرورگر Aether را نصب، اجرا و پایش کن.",
    lang_label: "زبان",
    vpn_title: "نکته مهم درباره VPN",
    vpn_body: "برای اجرای واقعی Aether بهتر است VPN سیستم خاموش باشد. برای دانلود یا آپدیت، اگر لازم شد می‌توانی موقتاً VPN را روشن کنی.",
    tab_overview: "نمای کلی",
    tab_settings: "تنظیمات",
    tab_logs: "لاگ‌ها",
    tab_help: "راهنما",
    presets_title: "پریست‌های آماده",
    presets_desc: "برای شروع سریع، یکی از این پروفایل‌ها را انتخاب کن.",
    smart_title: "اتصال هوشمند",
    smart_desc: "یک کلیک برای اتصال، توقف و اعمال بهترین تنظیمات بر اساس وضعیت شبکه و دسته‌بندی استفاده.",
    smart_idle_title: "غیرفعال",
    smart_idle_sub: "برای شروع، دسته‌بندی را انتخاب کن.",
    smart_stop_sub: "برای توقف اتصال کلیک کن.",
    smart_start_sub: "برای اتصال هوشمند کلیک کن.",
    smart_failed_title: "عدم اتصال",
    smart_failed_sub: "تنظیمات سخت‌گیرانه‌تر یا دسته‌بندی دیگر را امتحان کن.",
    smart_stopped_title: "متوقف",
    smart_stopped_sub: "آخرین اتصال متوقف شده؛ برای وصل شدن دوباره کلیک کن.",
    smart_ready_title: "وصل",
    smart_ready_sub: "اتصال تأیید شده و آماده استفاده است.",
    smart_scanning_title: "در حال اتصال",
    smart_scanning_sub: "در حال اسکن و اعتبارسنجی مسیر...",
    network_title_online: "اینترنت سیستم",
    network_title_connection: "نوع اتصال",
    network_title_proxy: "سلامت پراکسی",
    network_title_hint: "پیشنهاد هوشمند",
    network_online: "آنلاین",
    network_offline: "آفلاین",
    network_unknown: "نامشخص",
    hint_h3: "UDP/QUIC باز به‌نظر می‌رسد؛ h3 یا استریم مناسب است.",
    hint_h2: "برای وب و سوشیال یا شبکه‌های سخت‌گیر، h2 مناسب‌تر است.",
    hint_strict: "با توجه به خطاهای اخیر، حالت ضد DPI پیشنهاد می‌شود.",
    hint_gaming: "اگر بازی مهم است، اول WireGuard را امتحان کن. اگر ناپایدار بود برگرد روی MASQUE.",
    diag_title: "تشخیص سریع",
    diag_desc: "این بخش با توجه به وضعیت فعلی، پیشنهادهای سریع می‌دهد.",
    action_title: "خروجی آخرین عملیات",
    action_desc: "نتیجه‌ی نصب، آپدیت، تست پراکسی و خطاهای خلاصه‌شده اینجا نمایش داده می‌شود.",
    config_title: "تنظیمات اجرا",
    config_desc: "تنظیمات ذخیره می‌شوند و برای دفعات بعدی باقی می‌مانند.",
    preview_title: "دستور نهایی",
    preview_desc: "همان چیزی که داشبورد برای اجرای Aether استفاده می‌کند.",
    logs_title: "لاگ زنده",
    logs_desc: "خروجی مستقیم خود Aether. هر چند ثانیه رفرش می‌شود.",
    guide_title: "راهنمای سریع",
    guide_desc: "چک‌لیست شروع، تنظیم پراکسی، و عیب‌یابی.",
    guide_quick_title: "شروع در ۳۰ ثانیه",
    guide_udp_title: "اگر UDP یا QUIC بسته بود",
    guide_tls_title: "اگر TLS ClientHello بسته می‌شود",
    guide_browser_title: "تنظیم پراکسی مرورگر",
    guide_lan_title: "دسترسی از لپ‌تاپ یا دستگاه دیگر",
    lite_title: "حالت بدون Termux / Lite Mode",
    lite_body: "اگر پنل بدون بک‌اند Termux باز شود، همچنان می‌توانی پریست‌ها را ببینی، کانفیگ را ویرایش و export/import کنی، ولی اجرای واقعی هسته Aether نیاز به Termux یا یک بک‌اند سازگار دارد.",
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
    label_mode: "Mode",
    label_ready: "آماده برای استفاده",
    label_binary: "Aether binary",
    label_log_file: "Log file",
    version_prefix: "نسخه:",
    auto_refresh: "رفرش خودکار",
    btn_install: "نصب Aether",
    btn_start: "اجرای Aether",
    btn_stop: "توقف",
    btn_restart: "ری‌استارت",
    btn_test: "تست پراکسی",
    btn_copy_socks: "کپی SOCKS",
    btn_run_site_checks: "تست سایت‌ها",
    btn_copy_sitechecks: "کپی نتیجه",
    btn_save: "ذخیره تنظیمات",
    btn_update_core: "آپدیت هسته",
    btn_update_panel: "آپدیت پنل",
    btn_uninstall: "حذف",
    btn_refresh_logs: "رفرش لاگ",
    btn_clear: "پاک کردن",
    btn_view_simple: "حالت ساده",
    btn_view_advanced: "حالت پیشرفته",
    btn_copy_command: "کپی دستور",
    btn_copy_logs: "کپی لاگ",
    btn_copy_diag: "کپی تشخیص",
    btn_export: "اکسپورت کانفیگ",
    btn_import: "ایمپورت کانفیگ",
    btn_install_pwa: "نصب به‌عنوان اپ",
    btn_generate_qr: "ساخت QR",
    btn_copy_qr: "کپی متن QR",
    btn_copy_link: "کپی لینک",
    btn_scan_qr: "اسکن QR",
    btn_apply_payload: "اعمال متن",
    btn_backup_now: "بکاپ دستی",
    btn_clear_backups: "حذف همه",
    btn_clear_history: "پاک کردن سابقه",
    btn_clear_notifications: "پاک کردن اعلان‌ها",
    btn_close_camera: "بستن",
    btn_restore: "بازیابی",
    btn_apply: "اعمال",
    btn_delete: "حذف",
    history_title: "پروفایل‌های موفق اخیر",
    history_desc: "آخرین اجراها و تست‌های موفق اینجا ذخیره می‌شوند تا سریع دوباره برگردی.",
    sitechecks_title: "تست سایت‌های مهم",
    sitechecks_desc: "چند سایت مهم و معمولاً فیلترشده از داخل همین SOCKS5 تست می‌شوند تا بفهمی تونل واقعاً کار می‌کند یا نه.",
    notif_title: "تاریخچه اعلان‌ها",
    notif_desc: "تست‌ها، آپدیت‌ها و خطاهای اخیر اینجا ذخیره می‌شوند.",
    backup_title: "نسخه‌های پشتیبان کانفیگ",
    backup_desc: "هر بار ذخیره یا ایمپورت، یک نسخه‌ی پشتیبان محلی ساخته می‌شود.",
    qr_title: "انتقال کانفیگ با QR",
    qr_desc: "کانفیگ فعلی را به‌صورت QR و متن فشرده برای دستگاه دیگر آماده کن.",
    qr_payload_label: "متن فشرده‌ی کانفیگ",
    sitechecks_empty: "هنوز تست سایتی اجرا نشده است.",
    notif_empty: "هنوز هیچ اعلانی ذخیره نشده است.",
    history_empty: "هنوز هیچ اجرای موفقی ثبت نشده است.",
    backup_empty: "هنوز هیچ بکاپی ساخته نشده است.",
    qr_placeholder: "QR",
    backup_created: "نسخه‌ی پشتیبان ذخیره شد.",
    history_cleared: "سابقه پاک شد.",
    backups_cleared: "بکاپ‌ها حذف شدند.",
    notifications_cleared: "اعلان‌ها پاک شدند.",
    backup_restored: "بکاپ بازیابی شد.",
    backup_deleted: "بکاپ حذف شد.",
    history_applied: "پروفایل دوباره اعمال شد.",
    qr_generated: "QR کانفیگ ساخته شد.",
    qr_link_copied: "لینک اشتراک کانفیگ کپی شد.",
    qr_applied: "کانفیگ از روی payload اعمال شد.",
    qr_scan_failed: "اسکن QR روی این دستگاه یا مرورگر پشتیبانی نشد یا چیزی پیدا نشد.",
    socks_copied: "پروفایل SOCKS5 کپی شد.",
    sitechecks_done: "تست سایت‌ها انجام شد.",
    installed_text: "نصب شده",
    not_installed: "نصب نشده",
    mode_termux: "Termux / Live",
    mode_lite: "Browser / Lite",
    status_idle: "آماده",
    status_running: "در حال اجرا",
    status_stopped: "متوقف",
    health_ok: "سالم",
    health_fail: "ناسالم",
    health_unknown: "نامشخص",
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
    copy_success: "کپی شد.",
    import_success: "کانفیگ با موفقیت وارد شد.",
    view_simple_toast: "حالت ساده فعال شد.",
    view_advanced_toast: "حالت پیشرفته فعال شد.",
    pwa_install_toast: "نسخه‌ی قابل نصب مرورگری آماده شد.",
    lite_mode_toast: "پنل در حالت Lite باز شد؛ برای اجرای واقعی Aether باید بک‌اند Termux در دسترس باشد.",
    confirm_uninstall: "Aether uninstall شود؟",
    op_completed: "عملیات انجام شد",
    op_failed: "خطا",
    quick_list_html: "<li>روی <strong>نصب Aether</strong> بزن.</li><li>پریست <strong>ایران / حالت پیشنهادی</strong> را انتخاب کن.</li><li>روی <strong>ذخیره تنظیمات</strong> و بعد <strong>اجرای Aether</strong> بزن.</li><li>پراکسی مرورگر را روی <code>127.0.0.1:1819</code> با نوع <code>SOCKS5</code> تنظیم کن.</li><li>با <strong>تست پراکسی</strong> مطمئن شو ترافیک عبور می‌کند.</li>",
    udp_body_html: "پریست <strong>UDP بسته است</strong> را انتخاب کن. این حالت از MASQUE روی h2/TCP استفاده می‌کند.",
    tls_body_html: "پریست <strong>DPI سخت‌گیر</strong> را امتحان کن یا در بخش MASQUE گزینه <strong>Fragment TLS ClientHello</strong> را برای h2 روشن کن.",
    browser_list_html: "<li>Host: <code>127.0.0.1</code></li><li>Port: <code>1819</code></li><li>Type: <code>SOCKS5</code></li><li>اگر ممکن بود DNS هم از داخل پراکسی عبور کند.</li>",
    lan_body_html: "داشبورد را با <code>aether-web --host 0.0.0.0 --port 8787</code> اجرا کن و فقط روی شبکه محلی مطمئن از آن استفاده کن.",
    diag_binary_missing_title: "هسته Aether هنوز نصب نشده",
    diag_binary_missing_body: "اول روی «نصب Aether» یا «آپدیت هسته» بزن تا باینری داخل ترموکس قرار بگیرد.",
    diag_running_title: "Aether در حال اجراست",
    diag_running_body: "اگر ترافیک رد نمی‌شود، یک بار تست پراکسی را بزن و در صورت نیاز h2 یا fragmentation را امتحان کن.",
    diag_stopped_title: "Aether هنوز اجرا نشده",
    diag_stopped_body: "بعد از انتخاب پریست مناسب، روی «اجرای Aether» بزن.",
    diag_port_ok_title: "پورت پراکسی درست است",
    diag_port_ok_body: "پراکسی روی 127.0.0.1:1819 تنظیم شده؛ این همان پورت پیش‌فرض Aether است.",
    diag_port_custom_title: "پورت پراکسی تغییر کرده",
    diag_port_custom_body: "الان پراکسی روی {{bind}} است. اگر مرورگرت قبلاً روی 1819 بوده، تنظیمش را هماهنگ کن.",
    diag_port_conflict_title: "تداخل پورت پیدا شد",
    diag_port_conflict_body: "پورت پنل وب و پراکسی یکی شده‌اند. پورت پنل باید 8787 بماند و پراکسی 1819.",
    diag_vpn_title: "VPN سیستم را خاموش کن",
    diag_vpn_body: "برای اجرای واقعی Aether بهتر است VPN خاموش باشد. فقط برای دانلود یا آپدیت اگر لازم شد موقتاً روشنش کن.",
    diag_h3_title: "اگر QUIC/UDP بسته بود",
    diag_h3_body: "اگر MASQUE روی h3 وصل نمی‌شود، پریست «UDP بسته است» یا حالت h2/TCP را امتحان کن.",
    diag_h2_title: "اگر h2 handshake بسته می‌شود",
    diag_h2_body: "در حالت h2، اگر باز هم اتصال نمی‌گیرد، Fragment TLS ClientHello را روشن کن یا پریست DPI سخت‌گیر را بزن.",
    diag_legacy_title: "نسخه‌ی هسته قدیمی یا محدود است",
    diag_legacy_body: "باینری فعلی فلگ نسخه را کامل پشتیبانی نمی‌کند. بهتر است از داخل پنل، هسته را آپدیت کنی.",
    diag_version_ok_title: "نسخه‌ی هسته قابل تشخیص است",
    diag_version_ok_body: "{{version}}",
    diag_lite_title: "پنل در حالت Lite اجرا شده",
    diag_lite_body: "تو می‌توانی پریست‌ها، export/import و پیش‌نمایش دستور را بدون Termux استفاده کنی؛ ولی Start/Install واقعی نیاز به بک‌اند دارد.",
    diag_health_title: "آخرین وضعیت سلامت پراکسی",
    diag_health_ok_body: "آخرین تست سلامت موفق بود. زمان پاسخ حدود {{ms}}ms است.",
    diag_health_fail_body: "آخرین تست سلامت ناموفق بود. بهتر است تست پراکسی را دوباره اجرا کنی یا تنظیمات h2 / fragmentation را امتحان کنی.",
    action_ok_prefix: "✅",
    action_err_prefix: "❌",
    splash_loading: "در حال آماده‌سازی پنل...",
    splash_lite: "در حال ورود به حالت Lite...",
    splash_ready: "پنل آماده است.",
    ready_yes: "بله",
    ready_no: "نه",
    ready_scanning: "در حال اسکن",
    camera_title: "اسکن زنده QR",
    camera_desc: "دوربین را روبه‌روی QR بگیر تا کانفیگ خودکار خوانده شود.",
    camera_starting: "در حال آماده‌سازی دوربین...",
    camera_point: "QR را داخل کادر نگه دار.",
    camera_found: "QR پیدا شد؛ در حال اعمال کانفیگ...",
    log_filter_placeholder: "جستجو در لاگ‌ها",
  },
  en: {
    hero_eyebrow: "Aether / Termux / Local Dashboard",
    hero_title: "Aether Web Dashboard for Termux",
    hero_lead: "Install, run, stop, and monitor Aether from your browser without memorizing CLI flags.",
    lang_label: "Language",
    vpn_title: "Important VPN note",
    vpn_body: "For real Aether usage, it is better to keep your system VPN off. For downloads or updates, you can temporarily enable a VPN if needed.",
    tab_overview: "Overview",
    tab_settings: "Settings",
    tab_logs: "Logs",
    tab_help: "Help",
    presets_title: "Ready-made presets",
    presets_desc: "Pick one of these profiles for a fast start.",
    smart_title: "Smart connect",
    smart_desc: "One click to connect, stop, and apply sensible settings based on network conditions and usage category.",
    smart_idle_title: "Idle",
    smart_idle_sub: "Choose a category and tap to connect.",
    smart_stop_sub: "Tap to stop the current tunnel.",
    smart_start_sub: "Tap for a smart connection attempt.",
    smart_failed_title: "Failed",
    smart_failed_sub: "Try a stricter profile or another category.",
    smart_stopped_title: "Stopped",
    smart_stopped_sub: "The previous tunnel was stopped. Tap to connect again.",
    smart_ready_title: "Connected",
    smart_ready_sub: "The tunnel is validated and ready for use.",
    smart_scanning_title: "Connecting",
    smart_scanning_sub: "Scanning and validating a working route...",
    network_title_online: "System internet",
    network_title_connection: "Connection type",
    network_title_proxy: "Proxy health",
    network_title_hint: "Smart hint",
    network_online: "Online",
    network_offline: "Offline",
    network_unknown: "Unknown",
    hint_h3: "UDP/QUIC looks available; h3 or streaming mode is a good first try.",
    hint_h2: "For web/social or stricter networks, h2 is usually the safer choice.",
    hint_strict: "Recent failures suggest a stricter anti-DPI profile.",
    hint_gaming: "If gaming is the priority, try WireGuard first. If it becomes unstable, fall back to MASQUE.",
    diag_title: "Quick diagnostics",
    diag_desc: "This section gives fast suggestions based on your current state.",
    action_title: "Latest action output",
    action_desc: "Install, update, proxy test, and summarized errors appear here.",
    config_title: "Run settings",
    config_desc: "Your settings are saved and reused next time.",
    preview_title: "Final command",
    preview_desc: "This is the exact command the dashboard will use to launch Aether.",
    logs_title: "Live logs",
    logs_desc: "Direct Aether output. Refreshed every few seconds.",
    guide_title: "Quick guide",
    guide_desc: "Startup checklist, proxy setup, and troubleshooting.",
    guide_quick_title: "Start in 30 seconds",
    guide_udp_title: "If UDP or QUIC is blocked",
    guide_tls_title: "If TLS ClientHello gets blocked",
    guide_browser_title: "Browser proxy setup",
    guide_lan_title: "Access from a laptop or another device",
    lite_title: "Lite mode / no-Termux capability",
    lite_body: "If the dashboard is opened without a Termux backend, you can still browse presets, edit config, and export/import settings, but real Aether execution still needs Termux or a compatible backend.",
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
    label_mode: "Mode",
    label_ready: "Ready",
    label_binary: "Aether binary",
    label_log_file: "Log file",
    version_prefix: "Version:",
    auto_refresh: "Auto refresh",
    btn_install: "Install Aether",
    btn_start: "Start Aether",
    btn_stop: "Stop",
    btn_restart: "Restart",
    btn_test: "Proxy Test",
    btn_save: "Save settings",
    btn_update_core: "Update Core",
    btn_update_panel: "Update Panel",
    btn_uninstall: "Uninstall",
    btn_refresh_logs: "Refresh logs",
    btn_clear: "Clear",
    btn_view_simple: "Simple mode",
    btn_view_advanced: "Advanced mode",
    btn_copy_command: "Copy command",
    btn_copy_logs: "Copy logs",
    btn_copy_diag: "Copy diagnostics",
    btn_export: "Export config",
    btn_import: "Import config",
    btn_install_pwa: "Install App",
    btn_generate_qr: "Generate QR",
    btn_copy_qr: "Copy QR payload",
    btn_copy_link: "Copy link",
    btn_scan_qr: "Scan QR",
    btn_apply_payload: "Apply payload",
    btn_backup_now: "Backup now",
    btn_clear_backups: "Delete all",
    btn_clear_history: "Clear history",
    btn_clear_notifications: "Clear notifications",
    btn_close_camera: "Close",
    btn_restore: "Restore",
    btn_apply: "Apply",
    btn_delete: "Delete",
    history_title: "Recent successful profiles",
    history_desc: "Your latest successful starts and proxy tests are kept here for quick reuse.",
    sitechecks_title: "Important site checks",
    sitechecks_desc: "A few important and commonly filtered sites are tested through this SOCKS5 proxy so you can confirm the tunnel really works.",
    notif_title: "Notification history",
    notif_desc: "Recent updates, proxy tests, and errors are stored here.",
    backup_title: "Config backup versions",
    backup_desc: "Every save or import creates a local config backup.",
    qr_title: "Transfer config with QR",
    qr_desc: "Prepare the current config as a QR code and compact text for another device.",
    qr_payload_label: "Compressed config payload",
    sitechecks_empty: "No site test has been run yet.",
    notif_empty: "No notifications have been stored yet.",
    history_empty: "No successful runs have been saved yet.",
    backup_empty: "No backups have been created yet.",
    qr_placeholder: "QR",
    backup_created: "Backup saved.",
    history_cleared: "History cleared.",
    backups_cleared: "Backups deleted.",
    notifications_cleared: "Notifications cleared.",
    backup_restored: "Backup restored.",
    backup_deleted: "Backup deleted.",
    history_applied: "Profile applied again.",
    qr_generated: "Config QR generated.",
    qr_link_copied: "Share link copied.",
    qr_applied: "Config was applied from payload.",
    qr_scan_failed: "QR scanning is not supported on this device/browser or no code was detected.",
    socks_copied: "SOCKS5 profile copied.",
    sitechecks_done: "Site checks completed.",
    installed_text: "installed",
    not_installed: "not installed",
    mode_termux: "Termux / Live",
    mode_lite: "Browser / Lite",
    status_idle: "Idle",
    status_running: "Running",
    status_stopped: "Stopped",
    health_ok: "Healthy",
    health_fail: "Unhealthy",
    health_unknown: "Unknown",
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
    copy_success: "Copied.",
    import_success: "Config imported successfully.",
    view_simple_toast: "Simple mode enabled.",
    view_advanced_toast: "Advanced mode enabled.",
    pwa_install_toast: "Installable app mode is ready.",
    lite_mode_toast: "The dashboard started in Lite mode; real Aether execution still needs a Termux backend.",
    confirm_uninstall: "Uninstall Aether?",
    op_completed: "Operation completed",
    op_failed: "Error",
    quick_list_html: "<li>Click <strong>Install Aether</strong>.</li><li>Choose the <strong>Iran / Recommended</strong> preset.</li><li>Click <strong>Save settings</strong> and then <strong>Start Aether</strong>.</li><li>Set your browser proxy to <code>127.0.0.1:1819</code> using <code>SOCKS5</code>.</li><li>Use <strong>Proxy Test</strong> to verify traffic really passes.</li>",
    udp_body_html: "Choose the <strong>UDP Blocked</strong> preset. It runs MASQUE over h2/TCP.",
    tls_body_html: "Try the <strong>Strict DPI</strong> preset, or enable <strong>Fragment TLS ClientHello</strong> for h2 in the MASQUE section.",
    browser_list_html: "<li>Host: <code>127.0.0.1</code></li><li>Port: <code>1819</code></li><li>Type: <code>SOCKS5</code></li><li>If possible, route DNS through the proxy too.</li>",
    lan_body_html: "Run the dashboard with <code>aether-web --host 0.0.0.0 --port 8787</code> and only use this mode on a trusted local network.",
    diag_binary_missing_title: "Aether core is not installed yet",
    diag_binary_missing_body: "Click Install Aether or Update Core first so the binary becomes available in Termux.",
    diag_running_title: "Aether is running",
    diag_running_body: "If traffic still does not pass, run Proxy Test and try h2 or fragmentation if needed.",
    diag_stopped_title: "Aether is not running yet",
    diag_stopped_body: "Choose a preset, save your settings, and then click Start Aether.",
    diag_port_ok_title: "Proxy port looks correct",
    diag_port_ok_body: "The proxy is set to 127.0.0.1:1819, which is the normal Aether default.",
    diag_port_custom_title: "Proxy port was changed",
    diag_port_custom_body: "The proxy is currently set to {{bind}}. Make sure your browser matches that value.",
    diag_port_conflict_title: "Port conflict detected",
    diag_port_conflict_body: "The web panel and proxy appear to share the same port. Keep the panel on 8787 and the proxy on 1819.",
    diag_vpn_title: "Turn off your system VPN",
    diag_vpn_body: "For real Aether sessions, it is better to keep the system VPN off. Only enable it temporarily for downloads or updates if needed.",
    diag_h3_title: "If QUIC/UDP is blocked",
    diag_h3_body: "If MASQUE on h3 does not connect, try the UDP Blocked preset or switch to h2/TCP.",
    diag_h2_title: "If the h2 handshake is blocked",
    diag_h2_body: "When using h2, enable Fragment TLS ClientHello or use the Strict DPI preset if the handshake still fails.",
    diag_legacy_title: "The core binary looks old or limited",
    diag_legacy_body: "The current binary does not fully support version flags. Updating the core is recommended.",
    diag_version_ok_title: "Core version detected",
    diag_version_ok_body: "{{version}}",
    diag_lite_title: "The dashboard is running in Lite mode",
    diag_lite_body: "You can still use presets, export/import, and command preview without Termux, but Start/Install actions need a backend.",
    diag_health_title: "Latest proxy health result",
    diag_health_ok_body: "The last health probe succeeded. Response time was about {{ms}}ms.",
    diag_health_fail_body: "The last health probe failed. Run Proxy Test again or try h2 / fragmentation if needed.",
    action_ok_prefix: "✅",
    action_err_prefix: "❌",
    splash_loading: "Preparing dashboard...",
    splash_lite: "Switching to Lite mode...",
    splash_ready: "Dashboard is ready.",
    ready_yes: "Yes",
    ready_no: "No",
    ready_scanning: "Scanning",
    ready_no: "No",
    ready_scanning: "Scanning",
    camera_title: "Live QR scanner",
    camera_desc: "Point the camera at a QR code to read and apply the config automatically.",
    camera_starting: "Preparing camera...",
    camera_point: "Keep the QR code inside the frame.",
    camera_found: "QR detected; applying config...",
    log_filter_placeholder: "Search logs",
  },
};

function preferredLanguage() {
  const saved = localStorage.getItem(STORAGE_KEYS.lang);
  if (saved === "fa" || saved === "en") return saved;
  return (navigator.language || "").toLowerCase().startsWith("fa") ? "fa" : "en";
}

function preferredViewMode() {
  return localStorage.getItem(STORAGE_KEYS.view) === "advanced" ? "advanced" : "simple";
}

function t(key) {
  const lang = state.lang || preferredLanguage();
  return translations[lang]?.[key] ?? translations.fa[key] ?? key;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function cloneValue(value) {
  return JSON.parse(JSON.stringify(value ?? {}));
}

function deepMerge(base, patch) {
  const out = cloneValue(base || {});
  Object.entries(patch || {}).forEach(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      out[key] = deepMerge(out[key] || {}, value);
    } else {
      out[key] = value;
    }
  });
  return out;
}

function interpolate(template, params = {}) {
  return Object.entries(params).reduce(
    (acc, [key, value]) => acc.replaceAll(`{{${key}}}`, value),
    template,
  );
}

function pushNotification(message, kind = "info") {
  const notifications = storageGetJson(STORAGE_KEYS.notifications, []);
  notifications.unshift({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    message,
    kind,
    createdAt: new Date().toISOString(),
  });
  state.notifications = notifications.slice(0, 24);
  storageSetJson(STORAGE_KEYS.notifications, state.notifications);
  renderNotifications();
}

function showToast(message, kind = "info") {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  el.style.borderColor = kind === "error" ? "rgba(255, 107, 136, 0.4)" : kind === "warn" ? "rgba(255, 200, 97, 0.4)" : "rgba(120, 177, 255, 0.18)";
  pushNotification(message, kind);
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add("hidden"), 4000);
}

function setSplash(text) {
  $("splashStatus").textContent = text;
}

function hideSplash() {
  setTimeout(() => $("splashScreen").classList.add("hidden"), 220);
}

function setActionOutput(title, text = "") {
  state.actionTitle = title;
  state.actionText = String(text || "").trim();
  $("actionOutputBox").textContent = state.actionText ? `${title}\n\n${state.actionText}` : title;
}

function summarizeText(text, fallback = t("op_failed")) {
  const raw = String(text || "").trim();
  if (!raw) return fallback;
  const lines = raw.split("\n").map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const lowered = line.toLowerCase();
    if (lowered.startsWith("usage:")) continue;
    return line.length > 180 ? `${line.slice(0, 177)}...` : line;
  }
  return lines[0] || fallback;
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

function setLanguage(lang) {
  state.lang = lang === "en" ? "en" : "fa";
  localStorage.setItem(STORAGE_KEYS.lang, state.lang);
  applyTranslations();
  renderPresets(state.lastPresets);
  renderDiagnostics();
  renderActionOutput();
  renderDocs(state.docs);
  renderLogs(state.rawLogs || "");
  updatePreviewFromForm();
  renderStatus();
}

function setViewMode(mode, announce = false) {
  state.viewMode = mode === "advanced" ? "advanced" : "simple";
  localStorage.setItem(STORAGE_KEYS.view, state.viewMode);
  document.body.classList.toggle("simple-mode", state.viewMode === "simple");
  $("viewModeBtn").textContent = state.viewMode === "simple" ? t("btn_view_advanced") : t("btn_view_simple");
  if (announce) showToast(state.viewMode === "simple" ? t("view_simple_toast") : t("view_advanced_toast"));
}

function storageGetJson(key, fallback = []) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : cloneValue(fallback);
  } catch {
    return cloneValue(fallback);
  }
}

function storageSetJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function humanNow() {
  return new Date().toLocaleString(state.lang === "fa" ? "fa-IR" : "en-US");
}

function protocolSummary(config) {
  const protocol = config.protocol === "wg" ? "WireGuard" : config.protocol === "gool" ? "GOOL" : "MASQUE";
  const transport = config.protocol === "masque" ? ` / ${config.masque.transport}` : "";
  const noise = config.noise_profile ? ` / ${config.noise_profile}` : "";
  return `${protocol}${transport}${noise}`;
}

function saveBackup(reason = "save", config = gatherConfig()) {
  const backups = storageGetJson(STORAGE_KEYS.backups, []);
  backups.unshift({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    label: reason,
    summary: protocolSummary(config),
    config,
  });
  state.backups = backups.slice(0, 12);
  storageSetJson(STORAGE_KEYS.backups, state.backups);
}

function loadBackups() {
  state.backups = storageGetJson(STORAGE_KEYS.backups, []);
}

function loadHistory() {
  state.histories = storageGetJson(STORAGE_KEYS.history, []);
}

function pushHistory(kind, config = gatherConfig()) {
  const histories = storageGetJson(STORAGE_KEYS.history, []);
  histories.unshift({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind,
    createdAt: new Date().toISOString(),
    summary: protocolSummary(config),
    config,
  });
  state.histories = histories.slice(0, 10);
  storageSetJson(STORAGE_KEYS.history, state.histories);
}

function applyTranslations() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("lang-en", state.lang === "en");
  $("langSwitcher").value = state.lang;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });

  $("installBtn").textContent = t("btn_install");
  $("startBtn").textContent = t("btn_start");
  $("stopBtn").textContent = t("btn_stop");
  $("restartBtn").textContent = t("btn_restart");
  $("testBtn").textContent = t("btn_test");
  $("copySocksBtn").textContent = t("btn_copy_socks");
  $("runSiteChecksBtn").textContent = t("btn_run_site_checks");
  $("copySiteChecksBtn").textContent = t("btn_copy_sitechecks");
  $("saveBtn").textContent = t("btn_save");
  $("updateBtn").textContent = t("btn_update_core");
  $("updatePanelBtn").textContent = t("btn_update_panel");
  $("viewModeBtn").textContent = state.viewMode === "simple" ? t("btn_view_advanced") : t("btn_view_simple");
  $("copyCommandBtn").textContent = t("btn_copy_command");
  $("copyLogsBtn").textContent = t("btn_copy_logs");
  $("copyDiagBtn").textContent = t("btn_copy_diag");
  $("exportConfigBtn").textContent = t("btn_export");
  $("importConfigBtn").textContent = t("btn_import");
  $("generateQrBtn").textContent = t("btn_generate_qr");
  $("copyQrPayloadBtn").textContent = t("btn_copy_qr");
  $("copyShareLinkBtn").textContent = t("btn_copy_link");
  $("scanQrBtn").textContent = t("btn_scan_qr");
  $("applyQrPayloadBtn").textContent = t("btn_apply_payload");
  $("createBackupBtn").textContent = t("btn_backup_now");
  $("clearBackupsBtn").textContent = t("btn_clear_backups");
  $("clearHistoryBtn").textContent = t("btn_clear_history");
  $("clearNotificationsBtn").textContent = t("btn_clear_notifications");
  $("installPwaBtn").textContent = t("btn_install_pwa");
  $("uninstallBtn").textContent = t("btn_uninstall");
  $("refreshLogsBtn").textContent = t("btn_refresh_logs");
  $("clearActionOutputBtn").textContent = t("btn_clear");
  $("closeCameraBtn").textContent = t("btn_close_camera");
  $("backendModeText").textContent = state.liteMode ? t("mode_lite") : t("mode_termux");

  $("guideQuickList").innerHTML = t("quick_list_html");
  $("guideUdpBody").innerHTML = t("udp_body_html");
  $("guideTlsBody").innerHTML = t("tls_body_html");
  $("guideBrowserList").innerHTML = t("browser_list_html");
  $("guideLanBody").innerHTML = t("lan_body_html");
  $("qrPlaceholder").textContent = t("qr_placeholder");
  $("qrPayload").placeholder = t("qr_payload_label");
  $("logSearchInput").placeholder = t("log_filter_placeholder");
  $("cameraStatus").textContent = t("camera_starting");
}

function enableTab(name) {
  document.querySelectorAll(".tab-btn").forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `tab-${name}`));
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
  state.config = deepMerge(DEFAULT_CONFIG, cfg || {});
  $("bindAddress").value = state.config.bind_address || "127.0.0.1:1819";
  $("protocol").value = state.config.protocol || "masque";
  $("scanMode").value = state.config.scan_mode || "balanced";
  $("ipMode").value = state.config.ip_mode || "v4";
  $("quickReconnect").value = state.config.quick_reconnect || "ask";
  populateNoiseOptions(state.config.protocol, state.config.noise_profile || currentNoiseDefault(state.config.protocol));
  $("verbose").checked = !!state.config.verbose;
  $("peer").value = state.config.peer || "";
  $("wgPeer").value = state.config.wg_peer || "";
  $("masqueTransport").value = state.config.masque.transport || "h3";
  $("h2Peer").value = state.config.masque.h2_peer || "";
  $("ech").value = state.config.masque.ech || "";
  $("fragment").checked = !!state.config.masque.fragment;
  $("fragmentSize").value = state.config.masque.fragment_size || "16-32";
  $("fragmentDelay").value = state.config.masque.fragment_delay || "2-10";
  $("validateSecs").value = state.config.masque.validate_secs || "10";
  $("masqueReconnectSecs").value = state.config.masque.reconnect_secs || "2";
  $("masqueNoDataCheck").checked = !!state.config.masque.no_data_check;
  $("keepalive").value = state.config.wireguard.keepalive || "5";
  $("wgReconnectSecs").value = state.config.wireguard.reconnect_secs || "2";
  $("wgNoDataCheck").checked = !!state.config.wireguard.no_data_check;
  $("noProfileRetry").checked = !!state.config.wireguard.no_profile_retry;
  $("binaryPath").value = state.config.advanced.binary_path || DEFAULT_CONFIG.advanced.binary_path;
  $("baseConfig").value = state.config.config_paths.base || "";
  $("wgConfig").value = state.config.config_paths.wg || "";
  $("masqueConfig").value = state.config.config_paths.masque || "";
  $("tlsGroups").value = state.config.advanced.tls_groups || "";
  $("extraArgs").value = state.config.advanced.extra_args || "";
  $("envBlock").value = state.config.advanced.env_block || "";
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

function syncVisibility() {
  const protocol = $("protocol").value;
  $("masqueFields").style.display = protocol === "masque" ? "block" : "none";
  $("wgFields").style.display = protocol === "wg" || protocol === "gool" ? "block" : "none";
  populateNoiseOptions(protocol, $("noiseProfile").value || currentNoiseDefault(protocol));
}

function presetText(preset, key) {
  return state.lang === "en"
    ? preset[`${key}_en`] || preset[`${key}_fa`] || preset[key] || ""
    : preset[`${key}_fa`] || preset[`${key}_en`] || preset[key] || "";
}

function renderPresets(presets) {
  state.lastPresets = presets || [];
  const container = $("presets");
  container.innerHTML = "";
  state.lastPresets.forEach((preset) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card";
    card.innerHTML = `<strong>${escapeHtml(presetText(preset, "label"))}</strong><p>${escapeHtml(presetText(preset, "description"))}</p>`;
    card.addEventListener("click", () => applyPreset(preset));
    container.appendChild(card);
  });
}

function renderDocs(docs) {
  state.docs = docs || [];
  const container = $("docsLinks");
  container.innerHTML = "";
  state.docs.forEach((doc) => {
    const link = document.createElement("a");
    link.href = doc.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = doc.name;
    container.appendChild(link);
  });
}

function loadNotifications() {
  state.notifications = storageGetJson(STORAGE_KEYS.notifications, []);
}

function renderNotifications() {
  const list = $("notificationsList");
  list.innerHTML = "";
  if (!state.notifications.length) {
    list.innerHTML = `<div class="notification-card"><p>${escapeHtml(t("notif_empty"))}</p></div>`;
    return;
  }
  state.notifications.forEach((item) => {
    const card = document.createElement("div");
    card.className = `notification-card ${item.kind || "info"}`;
    card.innerHTML = `<strong>${escapeHtml(item.message)}</strong><div class="notification-meta"><span>${escapeHtml(new Date(item.createdAt).toLocaleString(state.lang === "fa" ? "fa-IR" : "en-US"))}</span></div>`;
    list.appendChild(card);
  });
}

function renderSiteChecks() {
  const list = $("siteChecksList");
  list.innerHTML = "";
  if (!state.siteChecks.length) {
    list.innerHTML = `<div class="sitecheck-card"><p>${escapeHtml(t("sitechecks_empty"))}</p></div>`;
    return;
  }
  state.siteChecks.forEach((item) => {
    const card = document.createElement("div");
    card.className = `sitecheck-card ${item.ok ? "success" : "warn"}`;
    const latency = item.latency_ms != null ? `${item.latency_ms}ms` : "--";
    card.innerHTML = `
      <strong>${escapeHtml(item.name)}</strong>
      <p>${escapeHtml(item.url)}</p>
      <div class="sitecheck-meta">
        <span>HTTP ${escapeHtml(String(item.http_code || "000"))}</span>
        <span>${escapeHtml(latency)}</span>
      </div>
    `;
    list.appendChild(card);
  });
}

function currentConnectionLabel() {
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  return conn?.effectiveType || conn?.type || t("network_unknown");
}

function smartHintText() {
  if (!navigator.onLine) return t("network_offline");
  if (state.status?.last_exit_note && state.status.last_exit_note !== "stopped") return t("hint_strict");
  if (state.selectedCategory === "gaming") return t("hint_gaming");
  if (state.selectedCategory === "social") return t("hint_h2");
  const conn = currentConnectionLabel();
  if (String(conn).includes("2g") || String(conn).includes("3g")) return t("hint_h2");
  return t("hint_h3");
}

function renderCategories() {
  const grid = $("categoryGrid");
  if (!grid) return;
  grid.innerHTML = "";
  CATEGORY_PROFILES.forEach((category) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = `category-card ${state.selectedCategory === category.id ? "active" : ""}`;
    card.innerHTML = `<strong>${escapeHtml(state.lang === "en" ? category.label_en : category.label_fa)}</strong><p>${escapeHtml(state.lang === "en" ? category.description_en : category.description_fa)}</p>`;
    card.addEventListener("click", () => {
      state.selectedCategory = category.id;
      renderCategories();
      renderSmartPanel();
    });
    grid.appendChild(card);
  });
}

function renderNetworkMonitor() {
  const wrap = $("networkMonitor");
  if (!wrap) return;
  const proxyText = state.proxyHealth === true ? t("health_ok") : state.proxyHealth === false ? t("health_fail") : t("health_unknown");
  const onlineText = navigator.onLine ? t("network_online") : t("network_offline");
  const cards = [
    [t("network_title_online"), onlineText],
    [t("network_title_connection"), String(currentConnectionLabel())],
    [t("network_title_proxy"), proxyText],
    [t("network_title_hint"), smartHintText()],
  ];
  wrap.innerHTML = cards.map(([title, value]) => `<div class="network-card"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(value)}</span></div>`).join("");
}

function smartStateDescriptor() {
  if (state.smartBusy) return { cls: "smart-stopped", title: t("smart_scanning_title"), sub: t("smart_scanning_sub") };
  if (state.liteMode) return { cls: "smart-idle", title: t("smart_idle_title"), sub: t("diag_lite_body") };
  if (state.status?.running && state.proxyHealth === true) return { cls: "smart-ready", title: t("smart_ready_title"), sub: t("smart_stop_sub") };
  if (state.status?.running && state.proxyHealth === false) return { cls: "smart-failed", title: t("smart_failed_title"), sub: t("smart_failed_sub") };
  if (state.status?.last_exit_note === "stopped") return { cls: "smart-stopped", title: t("smart_stopped_title"), sub: t("smart_stopped_sub") };
  if (state.status?.last_exit_note && state.status?.last_exit_note !== "stopped") return { cls: "smart-failed", title: t("smart_failed_title"), sub: t("smart_failed_sub") };
  return { cls: "smart-idle", title: t("smart_idle_title"), sub: t("smart_start_sub") };
}

function renderSmartPanel() {
  const btn = $("smartConnectBtn");
  if (!btn) return;
  const desc = smartStateDescriptor();
  btn.className = `smart-connect ${desc.cls}`;
  $("smartStateLabel").textContent = desc.title;
  $("smartStateSub").textContent = desc.sub;
  renderCategories();
  renderNetworkMonitor();
}

function smartConfigForCategory(id) {
  const base = deepMerge(DEFAULT_CONFIG, {});
  base.quick_reconnect = "on";
  base.ip_mode = "v4";
  switch (id) {
    case "gaming":
      return deepMerge(base, { protocol: "wg", scan_mode: "balanced", noise_profile: "balanced", wireguard: { keepalive: "5", reconnect_secs: "2", no_profile_retry: false } });
    case "streaming":
      return deepMerge(base, { protocol: "masque", scan_mode: "balanced", noise_profile: "firewall", masque: { transport: "h3", fragment: false } });
    case "social":
      return deepMerge(base, { protocol: "masque", scan_mode: "balanced", noise_profile: "firewall", masque: { transport: "h2", fragment: true, fragment_size: "8-24", fragment_delay: "5-15" } });
    case "strict":
      return deepMerge(base, { protocol: "masque", scan_mode: "ironclad", noise_profile: "gfw", masque: { transport: "h2", fragment: true, fragment_size: "8-24", fragment_delay: "5-15" } });
    case "stable":
      return deepMerge(base, { protocol: "gool", scan_mode: "thorough", noise_profile: "aggressive", wireguard: { keepalive: "5", reconnect_secs: "2" } });
    case "auto":
    default:
      if (!navigator.onLine) return deepMerge(base, { protocol: "masque", scan_mode: "balanced", noise_profile: "firewall", masque: { transport: "h2", fragment: true, fragment_size: "8-24", fragment_delay: "5-15" } });
      if (state.status?.last_exit_note && state.status.last_exit_note !== "stopped") return smartConfigForCategory("strict");
      const conn = String(currentConnectionLabel());
      if (conn.includes("2g") || conn.includes("3g")) return smartConfigForCategory("social");
      return smartConfigForCategory("streaming");
  }
}

async function smartConnectToggle() {
  if (state.liteMode) {
    showToast(t("lite_mode_toast"), "warn");
    return;
  }
  state.smartBusy = true;
  renderSmartPanel();
  try {
    if (state.status?.running) {
      const result = await api("/api/stop", { method: "POST", body: JSON.stringify({}) });
      setActionOutput(`${t("action_ok_prefix")} ${t("stop_success")}`, result?.output || result?.message || "");
      showToast(t("stop_success"));
    } else {
      const smartConfig = smartConfigForCategory(state.selectedCategory || "auto");
      fillConfig(deepMerge(gatherConfig(), smartConfig));
      const config = await saveConfig(false);
      const result = await api("/api/start", { method: "POST", body: JSON.stringify({ config }) });
      pushHistory("start", config);
      renderHistory();
      setActionOutput(`${t("action_ok_prefix")} ${t("start_success")}`, result?.output || result?.message || "");
      showToast(t("start_success"));
    }
    renderActionOutput();
    await refreshStatus();
    await refreshLogs(true);
    await refreshHealth();
  } catch (error) {
    setActionOutput(`${t("action_err_prefix")} ${error.message || t("op_failed")}`, error.fullOutput || error.message || t("op_failed"));
    renderActionOutput();
    showToast(error.message || t("op_failed"), "error");
  } finally {
    state.smartBusy = false;
    renderSmartPanel();
  }
}

function renderHistory() {
  const list = $("historyList");
  list.innerHTML = "";
  if (!state.histories.length) {
    list.innerHTML = `<div class="history-card"><p>${escapeHtml(t("history_empty"))}</p></div>`;
    return;
  }
  state.histories.forEach((item) => {
    const card = document.createElement("div");
    card.className = "history-card";
    const kindLabel = item.kind === "test" ? t("btn_test") : t("btn_start");
    card.innerHTML = `
      <strong>${escapeHtml(item.summary)}</strong>
      <p>${escapeHtml(kindLabel)}</p>
      <div class="history-meta"><span>${escapeHtml(new Date(item.createdAt).toLocaleString(state.lang === "fa" ? "fa-IR" : "en-US"))}</span></div>
      <div class="history-actions">
        <button class="btn ghost compact history-apply" data-id="${escapeHtml(item.id)}">${escapeHtml(t("btn_apply"))}</button>
      </div>
    `;
    list.appendChild(card);
  });
}

function renderBackups() {
  const list = $("backupList");
  list.innerHTML = "";
  if (!state.backups.length) {
    list.innerHTML = `<div class="backup-card"><p>${escapeHtml(t("backup_empty"))}</p></div>`;
    return;
  }
  state.backups.forEach((item) => {
    const card = document.createElement("div");
    card.className = "backup-card";
    card.innerHTML = `
      <strong>${escapeHtml(item.summary || item.label || "Backup")}</strong>
      <p>${escapeHtml(item.label || "save")}</p>
      <div class="backup-meta"><span>${escapeHtml(new Date(item.createdAt).toLocaleString(state.lang === "fa" ? "fa-IR" : "en-US"))}</span></div>
      <div class="backup-actions">
        <button class="btn ghost compact backup-restore" data-id="${escapeHtml(item.id)}">${escapeHtml(t("btn_restore"))}</button>
        <button class="btn ghost compact backup-delete" data-id="${escapeHtml(item.id)}">${escapeHtml(t("btn_delete"))}</button>
      </div>
    `;
    list.appendChild(card);
  });
}

function encodePayloadUtf8(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function decodePayloadUtf8(payload) {
  return decodeURIComponent(escape(atob(payload.trim())));
}

function buildQrPayload(config = gatherConfig()) {
  const minimal = {
    bind_address: config.bind_address,
    protocol: config.protocol,
    scan_mode: config.scan_mode,
    ip_mode: config.ip_mode,
    quick_reconnect: config.quick_reconnect,
    noise_profile: config.noise_profile,
    masque: config.masque,
    wireguard: config.wireguard,
  };
  return encodePayloadUtf8(JSON.stringify(minimal));
}

function payloadToConfig(payload) {
  const parsed = JSON.parse(decodePayloadUtf8(payload));
  return deepMerge(DEFAULT_CONFIG, parsed);
}

function buildShareLink(payload = buildQrPayload(gatherConfig())) {
  return `${window.location.origin}${window.location.pathname}#cfg=${encodeURIComponent(payload)}`;
}

function applyPayload(payload) {
  let value = String(payload || "").trim();
  if (/^https?:\/\//i.test(value) && value.includes("#cfg=")) {
    const url = new URL(value);
    value = decodeURIComponent(url.hash.replace(/^#cfg=/, ""));
  }
  const config = payloadToConfig(value);
  fillConfig(config);
  updatePreviewFromForm();
  saveBackup("qr", gatherConfig());
  renderBackups();
  showToast(t("qr_applied"));
}

function renderQrPayload() {
  const payload = buildQrPayload(gatherConfig());
  $("qrPayload").value = payload;
  const url = `https://quickchart.io/qr?text=${encodeURIComponent(payload)}&size=320`;
  $("qrPreview").src = url;
  $("qrPreview").classList.remove("hidden");
  $("qrPlaceholder").classList.add("hidden");
  state.shareLink = buildShareLink(payload);
}

async function scanQrFromFile(file) {
  if (!("BarcodeDetector" in window)) throw new Error(t("qr_scan_failed"));
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const bitmap = await createImageBitmap(file);
  const results = await detector.detect(bitmap);
  if (!results.length || !results[0].rawValue) throw new Error(t("qr_scan_failed"));
  return results[0].rawValue;
}

async function stopCameraScan() {
  if (state.cameraStream) {
    state.cameraStream.getTracks().forEach((track) => track.stop());
    state.cameraStream = null;
  }
  if (state.cameraFrame) {
    cancelAnimationFrame(state.cameraFrame);
    state.cameraFrame = null;
  }
  $("cameraModal").classList.add("hidden");
  $("cameraVideo").srcObject = null;
}

async function startCameraScan() {
  if (!("BarcodeDetector" in window) || !navigator.mediaDevices?.getUserMedia) {
    $("qrImportFile").click();
    return;
  }

  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  $("cameraStatus").textContent = t("camera_starting");
  $("cameraModal").classList.remove("hidden");

  try {
    state.cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
    const video = $("cameraVideo");
    video.srcObject = state.cameraStream;
    await video.play();
    $("cameraStatus").textContent = t("camera_point");

    const tick = async () => {
      try {
        const results = await detector.detect(video);
        if (results.length && results[0].rawValue) {
          $("cameraStatus").textContent = t("camera_found");
          const raw = results[0].rawValue;
          await stopCameraScan();
          if (/^https?:\/\//i.test(raw) && raw.includes("#cfg=")) {
            const url = new URL(raw);
            const payload = url.hash.replace(/^#cfg=/, "");
            applyPayload(decodeURIComponent(payload));
          } else {
            applyPayload(raw);
          }
          return;
        }
      } catch {
        // ignore and continue scanning
      }
      state.cameraFrame = requestAnimationFrame(tick);
    };

    state.cameraFrame = requestAnimationFrame(tick);
  } catch (error) {
    await stopCameraScan();
    showToast(error.message || t("qr_scan_failed"), "error");
  }
}

function importPayloadFromHash() {
  const hash = window.location.hash || "";
  const match = hash.match(/#cfg=([^&]+)/);
  if (!match) return false;
  try {
    const payload = decodeURIComponent(match[1]);
    applyPayload(payload);
    history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    return true;
  } catch {
    showToast(t("qr_scan_failed"), "error");
    return false;
  }
}

function renderStatus() {
  const status = state.status;
  const bind = status?.config?.bind_address || state.config.bind_address;
  $("proxyAddr").textContent = bind;
  $("pidValue").textContent = status?.pid || "--";
  $("uptimeValue").textContent = status?.running ? status.uptime_human : "--";
  const versionText = status?.binary?.version || (status?.binary?.exists ? t("installed_text") : t("not_installed"));
  $("binaryVersion").textContent = `${t("version_prefix")} ${versionText}`;
  $("binaryPathView").textContent = status?.binary?.path || state.config.advanced.binary_path;
  $("logPathView").textContent = status?.log_file || "--";
  $("serverUrls").textContent = (status?.urls || [window.location.origin]).join("  |  ");
  $("backendModeText").textContent = state.liteMode ? t("mode_lite") : t("mode_termux");
  const readyText = state.liteMode ? t("ready_no") : status?.running ? (state.proxyHealth === true ? t("ready_yes") : t("ready_scanning")) : t("ready_no");
  $("readyStateText").textContent = readyText;

  const runBadge = $("runningBadge");
  runBadge.className = "badge";
  if (state.liteMode) {
    runBadge.classList.add("info");
    runBadge.textContent = t("mode_lite");
  } else if (status?.running) {
    runBadge.classList.add("running");
    runBadge.textContent = t("status_running");
  } else if (status?.last_exit_note) {
    runBadge.classList.add("error");
    runBadge.textContent = `${t("status_stopped")} (${status.last_exit_note})`;
  } else {
    runBadge.classList.add("idle");
    runBadge.textContent = t("status_idle");
  }

  const healthBadge = $("healthBadge");
  healthBadge.className = "badge small";
  if (state.proxyHealth === true) {
    healthBadge.classList.add("running");
    healthBadge.textContent = `Proxy: ${t("health_ok")}`;
  } else if (state.proxyHealth === false) {
    healthBadge.classList.add("warn");
    healthBadge.textContent = `Proxy: ${t("health_fail")}`;
  } else {
    healthBadge.classList.add("idle");
    healthBadge.textContent = `Proxy: ${t("health_unknown")}`;
  }

  const disabled = state.liteMode;
  ["installBtn", "startBtn", "stopBtn", "restartBtn", "testBtn", "saveBtn", "updateBtn", "updatePanelBtn", "uninstallBtn"].forEach((id) => {
    $(id).disabled = false;
  });
  if (disabled) {
    ["installBtn", "startBtn", "stopBtn", "restartBtn", "testBtn", "updateBtn", "updatePanelBtn", "uninstallBtn"].forEach((id) => {
      $(id).disabled = true;
    });
  }
}

function renderActionOutput() {
  const title = state.actionTitle || t("no_action_yet");
  const text = state.actionText || "";
  $("actionOutputBox").textContent = text ? `${title}\n\n${text}` : title;
}

function stripAnsi(text) {
  return String(text || "").replace(/\u001b\[[0-9;]*m/g, "");
}

function renderLogs(text) {
  state.rawLogs = text || state.rawLogs || "";
  const box = $("logsBox");
  const search = ($("logSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.logFilter || "all";
  if (!state.rawLogs) {
    box.innerHTML = escapeHtml(t("no_logs"));
    return;
  }

  const rows = stripAnsi(state.rawLogs).split("\n").map((line) => {
    const lowered = line.toLowerCase();
    let level = "dim";
    if (/(error|failed|panic|fatal|cannot)/.test(lowered)) level = "error";
    else if (/(warn|warning)/.test(lowered)) level = "warn";
    else if (/(success|installed|ready|started|running|ok)/.test(lowered)) level = "success";
    else if (/(info|debug|trace|scan|proxy|listen)/.test(lowered)) level = "info";
    return { line, level };
  }).filter((row) => {
    const matchesFilter = filter === "all" ? true : row.level === filter;
    const matchesSearch = !search || row.line.toLowerCase().includes(search);
    return matchesFilter && matchesSearch;
  });

  if (!rows.length) {
    box.innerHTML = escapeHtml(t("no_logs"));
    return;
  }

  box.innerHTML = rows.map((row) => `<span class="log-line log-${row.level}">${escapeHtml(row.line || " ")}</span>`).join("");
  box.scrollTop = box.scrollHeight;
}

function buildDiagnostics() {
  if (state.liteMode) {
    return [{ level: "info", title: t("diag_lite_title"), body: t("diag_lite_body") }];
  }
  const status = state.status || {};
  const items = [];
  const bind = status?.config?.bind_address || state.config.bind_address || "127.0.0.1:1819";
  const panelPort = String(status?.port || (window.location.port || "8787"));
  const bindPort = bind.includes(":") ? bind.split(":").pop() : bind;
  const binaryVersion = String(status?.binary?.version || "");
  const protocol = status?.config?.protocol || state.config.protocol;
  const transport = status?.config?.masque?.transport || state.config.masque.transport;

  if (!status?.binary?.exists) {
    items.push({ level: "error", title: t("diag_binary_missing_title"), body: t("diag_binary_missing_body") });
  } else {
    items.push({ level: "success", title: t("diag_version_ok_title"), body: interpolate(t("diag_version_ok_body"), { version: binaryVersion || t("installed_text") }) });
    if (binaryVersion.includes("unsupported")) {
      items.push({ level: "warn", title: t("diag_legacy_title"), body: t("diag_legacy_body") });
    }
  }

  if (bindPort === panelPort) {
    items.push({ level: "error", title: t("diag_port_conflict_title"), body: t("diag_port_conflict_body") });
  } else if (bind === "127.0.0.1:1819") {
    items.push({ level: "success", title: t("diag_port_ok_title"), body: t("diag_port_ok_body") });
  } else {
    items.push({ level: "info", title: t("diag_port_custom_title"), body: interpolate(t("diag_port_custom_body"), { bind }) });
  }

  if (status?.running) {
    items.push({ level: "success", title: t("diag_running_title"), body: t("diag_running_body") });
  } else {
    items.push({ level: "warn", title: t("diag_stopped_title"), body: t("diag_stopped_body") });
  }

  items.push({ level: state.proxyHealth ? "success" : "warn", title: t("diag_health_title"), body: state.proxyHealth ? interpolate(t("diag_health_ok_body"), { ms: String(state.proxyHealthDetail?.latency_ms ?? "--") }) : t("diag_health_fail_body") });
  items.push({ level: "warn", title: t("diag_vpn_title"), body: t("diag_vpn_body") });
  if (protocol === "masque" && transport === "h3") items.push({ level: "info", title: t("diag_h3_title"), body: t("diag_h3_body") });
  if (protocol === "masque" && transport === "h2") items.push({ level: "info", title: t("diag_h2_title"), body: t("diag_h2_body") });
  return items;
}

function renderDiagnostics() {
  const list = $("diagnosticsList");
  list.innerHTML = "";
  buildDiagnostics().forEach((item) => {
    const card = document.createElement("div");
    card.className = `diag-card ${item.level}`;
    card.innerHTML = `<strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.body)}</p>`;
    list.appendChild(card);
  });
}

function renderAll() {
  applyTranslations();
  renderSmartPanel();
  renderPresets(state.lastPresets);
  renderDocs(state.docs);
  renderStatus();
  renderActionOutput();
  renderDiagnostics();
  renderSiteChecks();
  renderNotifications();
  renderHistory();
  renderBackups();
  renderLogs(state.rawLogs || "");
  updatePreviewFromForm();
  renderQrPayload();
}

function applyPreset(preset) {
  const merged = deepMerge(state.config, preset.config || {});
  if (!(preset.config || {}).noise_profile) merged.noise_profile = currentNoiseDefault(merged.protocol);
  fillConfig(merged);
  updatePreviewFromForm();
  showToast(`${t("action_ok_prefix")} ${presetText(preset, "label")}`);
}

async function saveConfig(showMessage = true) {
  state.config = gatherConfig();
  saveBackup("save", state.config);
  if (state.liteMode) {
    localStorage.setItem(STORAGE_KEYS.liteConfig, JSON.stringify(state.config));
    if (showMessage) showToast(t("save_success"));
    renderAll();
    return state.config;
  }
  const data = await api("/api/config", { method: "POST", body: JSON.stringify({ config: state.config }) });
  state.config = data.config;
  if (showMessage) showToast(t("save_success"));
  renderAll();
  return state.config;
}

function buildPreviewFromConfig(config) {
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
    config.advanced.env_block.split("\n").map((line) => line.trim()).filter(Boolean).forEach((line) => env.push(line));
  }
  if (config.advanced.extra_args?.trim()) args.push(config.advanced.extra_args.trim());
  return `${env.join(" ")} ${args.join(" ")}`.trim();
}

function updatePreviewFromForm() {
  state.config = gatherConfig();
  $("commandPreview").textContent = buildPreviewFromConfig(state.config) || "--";
  renderQrPayload();
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
      if (id === "protocol") syncVisibility();
      updatePreviewFromForm();
    });
  });
}

async function refreshStatus() {
  if (state.liteMode) return;
  const data = await api("/api/status");
  state.status = data.status;
  state.docs = data.status.docs || state.docs;
  renderAll();
}

async function refreshLogs(force = false) {
  if (state.liteMode) return;
  if (!force && !$("autoRefreshLogs").checked) return;
  const data = await api("/api/logs?tail=250");
  renderLogs(data.log || "");
}

async function refreshHealth() {
  if (state.liteMode) return;
  try {
    const data = await api("/api/health");
    state.proxyHealth = !!data.ok;
    state.proxyHealthDetail = data;
  } catch {
    state.proxyHealth = false;
    state.proxyHealthDetail = null;
  }
  renderStatus();
  renderDiagnostics();
}

async function handleAction(button, work, successMessage) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "...";
  try {
    const result = await work();
    showToast(successMessage);
    setActionOutput(`${t("action_ok_prefix")} ${successMessage}`, result?.output || result?.message || "");
    renderActionOutput();
    await refreshStatus();
    await refreshLogs(true);
    await refreshHealth();
    return result;
  } catch (error) {
    setActionOutput(`${t("action_err_prefix")} ${error.message || t("op_failed")}`, error.fullOutput || error.message || t("op_failed"));
    renderActionOutput();
    showToast(error.message || t("op_failed"), "error");
    throw error;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function exportConfig() {
  const config = gatherConfig();
  const blob = new Blob([JSON.stringify(config, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aether-web-config.json";
  a.click();
  URL.revokeObjectURL(url);
  showToast(t("copy_success"));
}

function importConfigFromText(text) {
  const parsed = JSON.parse(text);
  fillConfig(deepMerge(DEFAULT_CONFIG, parsed));
  updatePreviewFromForm();
  showToast(t("import_success"));
}

async function copyText(text) {
  const value = String(text || "").trim();
  if (!value) return;
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
  } else {
    const area = document.createElement("textarea");
    area.value = value;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  showToast(t("copy_success"));
}

function buildSocksProfileText() {
  const bind = state.status?.config?.bind_address || state.config.bind_address || "127.0.0.1:1819";
  const [host, ...portParts] = bind.split(":");
  const port = portParts.length ? portParts.join(":") : "1819";
  return [
    "SOCKS5",
    `Host: ${host}`,
    `Port: ${port}`,
    "DNS through proxy: yes",
    `URI: socks5://${bind}`,
    "For v2rayNG or other apps: create a manual SOCKS5 outbound/profile with the values above.",
  ].join("\n");
}

async function runSiteChecks() {
  const result = await api("/api/site-checks");
  state.siteChecks = result.results || [];
  renderSiteChecks();
  return {
    ...result,
    output: (result.results || []).map((item) => `${item.ok ? "OK" : "FAIL"} | ${item.name} | HTTP ${item.http_code} | ${item.latency_ms ?? "--"}ms | ${item.url}`).join("\n"),
  };
}

function setMenu(open) {
  state.menuOpen = !!open;
  $("hamburgerMenu").classList.toggle("hidden", !state.menuOpen);
  $("hamburgerMenu").classList.toggle("open", state.menuOpen);
}

function buildSmartSummaryText() {
  const desc = smartStateDescriptor();
  const bind = state.status?.config?.bind_address || state.config.bind_address || "127.0.0.1:1819";
  return [
    `State: ${desc.title}`,
    `Category: ${state.selectedCategory}`,
    `Proxy: ${bind}`,
    `System online: ${navigator.onLine ? t("network_online") : t("network_offline")}`,
    `Connection: ${currentConnectionLabel()}`,
    `Hint: ${smartHintText()}`,
  ].join("\n");
}

function bindButtons() {
  $("installBtn").addEventListener("click", () => handleAction($("installBtn"), () => api("/api/install", { method: "POST", body: JSON.stringify({}) }), t("install_success")));
  $("startBtn").addEventListener("click", () => handleAction($("startBtn"), async () => {
    const config = await saveConfig(false);
    const result = await api("/api/start", { method: "POST", body: JSON.stringify({ config }) });
    pushHistory("start", config);
    renderHistory();
    return result;
  }, t("start_success")));
  $("stopBtn").addEventListener("click", () => handleAction($("stopBtn"), () => api("/api/stop", { method: "POST", body: JSON.stringify({}) }), t("stop_success")));
  $("restartBtn").addEventListener("click", () => handleAction($("restartBtn"), async () => {
    const config = await saveConfig(false);
    return api("/api/restart", { method: "POST", body: JSON.stringify({ config }) });
  }, t("restart_success")));
  $("testBtn").addEventListener("click", () => handleAction($("testBtn"), async () => {
    const result = await api("/api/test", { method: "POST", body: JSON.stringify({}) });
    pushHistory("test", gatherConfig());
    renderHistory();
    return result;
  }, t("test_success")));
  $("copySocksBtn").addEventListener("click", () => copyText(buildSocksProfileText()).then(() => showToast(t("socks_copied"))).catch((e) => showToast(e.message, "error")));
  $("runSiteChecksBtn").addEventListener("click", () => handleAction($("runSiteChecksBtn"), runSiteChecks, t("sitechecks_done")));
  $("copySiteChecksBtn").addEventListener("click", () => copyText((state.siteChecks || []).map((item) => `${item.ok ? "OK" : "FAIL"} | ${item.name} | HTTP ${item.http_code} | ${item.latency_ms ?? "--"}ms | ${item.url}`).join("\n") || t("sitechecks_empty")).catch((e) => showToast(e.message, "error")));
  $("saveBtn").addEventListener("click", () => handleAction($("saveBtn"), () => saveConfig(), t("save_success")));
  $("updateBtn").addEventListener("click", () => handleAction($("updateBtn"), () => api("/api/update", { method: "POST", body: JSON.stringify({}) }), t("core_update_success")));
  $("updatePanelBtn").addEventListener("click", () => handleAction($("updatePanelBtn"), () => api("/api/update-panel", { method: "POST", body: JSON.stringify({}) }), t("panel_update_success")));
  $("uninstallBtn").addEventListener("click", async () => {
    if (!confirm(t("confirm_uninstall"))) return;
    await handleAction($("uninstallBtn"), () => api("/api/uninstall", { method: "POST", body: JSON.stringify({}) }), t("uninstall_success"));
  });

  $("clearActionOutputBtn").addEventListener("click", () => {
    state.actionTitle = t("no_action_yet");
    state.actionText = "";
    renderActionOutput();
  });
  $("clearNotificationsBtn").addEventListener("click", () => {
    state.notifications = [];
    storageSetJson(STORAGE_KEYS.notifications, []);
    renderNotifications();
    showToast(t("notifications_cleared"));
  });
  $("refreshLogsBtn").addEventListener("click", () => refreshLogs(true));
  $("copyCommandBtn").addEventListener("click", () => copyText($("commandPreview").textContent).catch((e) => showToast(e.message, "error")));
  $("copyLogsBtn").addEventListener("click", () => copyText(stripAnsi(state.rawLogs || "")).catch((e) => showToast(e.message, "error")));
  $("copyDiagBtn").addEventListener("click", () => copyText(Array.from(document.querySelectorAll("#diagnosticsList .diag-card")).map((el) => el.innerText).join("\n\n")).catch((e) => showToast(e.message, "error")));

  $("exportConfigBtn").addEventListener("click", exportConfig);
  $("importConfigBtn").addEventListener("click", () => $("importConfigFile").click());
  $("generateQrBtn").addEventListener("click", () => {
    renderQrPayload();
    showToast(t("qr_generated"));
  });
  $("copyQrPayloadBtn").addEventListener("click", () => copyText($("qrPayload").value).catch((e) => showToast(e.message, "error")));
  $("copyShareLinkBtn").addEventListener("click", () => {
    renderQrPayload();
    copyText(state.shareLink || buildShareLink()).then(() => showToast(t("qr_link_copied"))).catch((e) => showToast(e.message, "error"));
  });
  $("applyQrPayloadBtn").addEventListener("click", () => {
    try {
      applyPayload($("qrPayload").value);
    } catch (error) {
      showToast(error.message || t("qr_scan_failed"), "error");
    }
  });
  $("scanQrBtn").addEventListener("click", () => startCameraScan());
  $("closeCameraBtn").addEventListener("click", () => stopCameraScan());
  $("cameraModal").addEventListener("click", (event) => {
    if (event.target.id === "cameraModal") stopCameraScan();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("cameraModal").classList.contains("hidden")) stopCameraScan();
  });
  $("createBackupBtn").addEventListener("click", () => {
    saveBackup("manual", gatherConfig());
    renderBackups();
    showToast(t("backup_created"));
  });
  $("clearBackupsBtn").addEventListener("click", () => {
    state.backups = [];
    storageSetJson(STORAGE_KEYS.backups, []);
    renderBackups();
    showToast(t("backups_cleared"));
  });
  $("clearHistoryBtn").addEventListener("click", () => {
    state.histories = [];
    storageSetJson(STORAGE_KEYS.history, []);
    renderHistory();
    showToast(t("history_cleared"));
  });
  $("importConfigFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      importConfigFromText(text);
      saveBackup("import", gatherConfig());
      renderBackups();
    } catch (error) {
      showToast(error.message || t("op_failed"), "error");
    }
    event.target.value = "";
  });

  $("qrImportFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const payload = await scanQrFromFile(file);
      $("qrPayload").value = payload;
      applyPayload(payload);
    } catch (error) {
      showToast(error.message || t("qr_scan_failed"), "error");
    }
    event.target.value = "";
  });

  $("langSwitcher").addEventListener("change", (event) => setLanguage(event.target.value));
  $("viewModeBtn").addEventListener("click", () => setViewMode(state.viewMode === "simple" ? "advanced" : "simple", true));
  $("logSearchInput").addEventListener("input", () => renderLogs());
  document.querySelectorAll("#logFilterChips .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      state.logFilter = chip.dataset.logFilter || "all";
      document.querySelectorAll("#logFilterChips .chip").forEach((btn) => btn.classList.toggle("active", btn === chip));
      renderLogs();
    });
  });
  $("installPwaBtn").addEventListener("click", async () => {
    if (!state.deferredPrompt) return;
    state.deferredPrompt.prompt();
    await state.deferredPrompt.userChoice;
    state.deferredPrompt = null;
    $("installPwaBtn").classList.add("hidden");
  });

  $("historyList").addEventListener("click", (event) => {
    const button = event.target.closest(".history-apply");
    if (!button) return;
    const item = state.histories.find((entry) => entry.id === button.dataset.id);
    if (!item) return;
    fillConfig(item.config);
    updatePreviewFromForm();
    enableTab("settings");
    showToast(t("history_applied"));
  });

  $("backupList").addEventListener("click", (event) => {
    const restoreBtn = event.target.closest(".backup-restore");
    const deleteBtn = event.target.closest(".backup-delete");
    if (restoreBtn) {
      const item = state.backups.find((entry) => entry.id === restoreBtn.dataset.id);
      if (!item) return;
      fillConfig(item.config);
      updatePreviewFromForm();
      showToast(t("backup_restored"));
      enableTab("settings");
      return;
    }
    if (deleteBtn) {
      state.backups = state.backups.filter((entry) => entry.id !== deleteBtn.dataset.id);
      storageSetJson(STORAGE_KEYS.backups, state.backups);
      renderBackups();
      showToast(t("backup_deleted"));
    }
  });

  $("smartConnectBtn").addEventListener("click", () => smartConnectToggle());
  $("copySmartSummaryBtn").addEventListener("click", () => copyText(buildSmartSummaryText()).catch((e) => showToast(e.message, "error")));
  $("menuToggleBtn").addEventListener("click", () => setMenu(!state.menuOpen));
  $("closeMenuBtn").addEventListener("click", () => setMenu(false));
  document.querySelectorAll("[data-tab-jump]").forEach((btn) => btn.addEventListener("click", () => {
    enableTab(btn.dataset.tabJump);
    setMenu(false);
  }));
  document.querySelectorAll(".tab-btn").forEach((btn) => btn.addEventListener("click", () => enableTab(btn.dataset.tab)));
  window.addEventListener("online", () => { renderSmartPanel(); renderStatus(); });
  window.addEventListener("offline", () => { renderSmartPanel(); renderStatus(); });
}

async function initializeBackend() {
  try {
    setSplash(t("splash_loading"));
    const [cfgData, statusData] = await Promise.all([api("/api/config"), api("/api/status")]);
    state.backendReady = true;
    state.liteMode = false;
    state.config = cfgData.config;
    state.lastPresets = cfgData.presets || statusData.status.presets || [];
    state.docs = cfgData.docs || statusData.status.docs || [];
    state.status = statusData.status;
    fillConfig(state.config);
    return true;
  } catch {
    setSplash(t("splash_lite"));
    state.backendReady = false;
    state.liteMode = true;
    const saved = localStorage.getItem(STORAGE_KEYS.liteConfig);
    state.config = saved ? deepMerge(DEFAULT_CONFIG, JSON.parse(saved)) : cloneValue(DEFAULT_CONFIG);
    state.lastPresets = FALLBACK_PRESETS;
    state.docs = [];
    state.status = {
      running: false,
      pid: null,
      uptime_human: "--",
      urls: [window.location.origin],
      port: window.location.port || "8787",
      config: state.config,
      binary: { path: state.config.advanced.binary_path, exists: false, version: t("not_installed") },
      log_file: "--",
      last_exit_note: null,
    };
    fillConfig(state.config);
    showToast(t("lite_mode_toast"));
    return false;
  }
}

async function registerPwa() {
  if ("serviceWorker" in navigator) {
    try {
      await navigator.serviceWorker.register("/service-worker.js");
    } catch {
      // ignore silently on local unsupported setups
    }
  }

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    state.deferredPrompt = event;
    $("installPwaBtn").classList.remove("hidden");
    showToast(t("pwa_install_toast"));
  });
}

function startPolling() {
  clearInterval(state.statusTimer);
  clearInterval(state.logsTimer);
  clearInterval(state.healthTimer);
  if (state.liteMode) return;

  state.statusTimer = setInterval(() => refreshStatus().catch(() => {}), 4000);
  state.logsTimer = setInterval(() => refreshLogs().catch(() => {}), 2800);
  state.healthTimer = setInterval(() => refreshHealth().catch(() => {}), 12000);
}

async function init() {
  state.lang = preferredLanguage();
  state.viewMode = preferredViewMode();
  state.selectedCategory = "auto";
  bindFormUpdates();
  bindButtons();
  await registerPwa();
  applyTranslations();
  setViewMode(state.viewMode);
  loadHistory();
  loadBackups();
  loadNotifications();
  setActionOutput(t("no_action_yet"));
  renderLogs("");
  enableTab("overview");

  await initializeBackend();
  importPayloadFromHash();
  renderAll();
  startPolling();
  if (!state.liteMode) {
    await refreshLogs(true).catch(() => {});
    await refreshHealth().catch(() => {});
  }
  setSplash(t("splash_ready"));
  hideSplash();
}

init().catch((error) => {
  setActionOutput(`${t("action_err_prefix")} ${t("op_failed")}`, error?.message || String(error));
  renderActionOutput();
  setSplash(t("op_failed"));
  setTimeout(hideSplash, 600);
});
