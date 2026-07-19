#!/usr/bin/env python3
"""Aether Termux Web App backend.

A small zero-dependency HTTP server for running and supervising the Aether
CLI from Termux through a browser.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

APP_VERSION = "1.0.0"
APP_TITLE = "Aether Termux Web"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = BASE_DIR / "docs"
DEFAULT_DATA_DIR = Path(os.environ.get("AETHER_WEB_DATA", Path.home() / ".config" / "aether-web"))
_DEFAULT_PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
DEFAULT_BINARY = Path(os.environ.get("AETHER_BINARY", str(Path(_DEFAULT_PREFIX) / "bin" / "aether")))
INSTALLER = BASE_DIR / "bin" / "aether-installer.sh"

DEFAULT_CONFIG: Dict[str, Any] = {
    "bind_address": "127.0.0.1:1819",
    "protocol": "masque",
    "scan_mode": "balanced",
    "ip_mode": "v4",
    "quick_reconnect": "ask",
    "noise_profile": "firewall",
    "verbose": True,
    "peer": "",
    "wg_peer": "",
    "masque": {
        "transport": "h3",
        "h2_peer": "",
        "ech": "",
        "fragment": False,
        "fragment_size": "16-32",
        "fragment_delay": "2-10",
        "validate_secs": "10",
        "reconnect_secs": "2",
        "no_data_check": False,
    },
    "wireguard": {
        "keepalive": "5",
        "reconnect_secs": "2",
        "no_data_check": False,
        "no_profile_retry": False,
    },
    "config_paths": {
        "base": "",
        "wg": "",
        "masque": "",
    },
    "advanced": {
        "binary_path": str(DEFAULT_BINARY),
        "tls_groups": "",
        "extra_args": "",
        "env_block": "",
    },
}

PRESETS: List[Dict[str, Any]] = [
    {
        "id": "iran-recommended",
        "label": "ایران / حالت پیشنهادی",
        "description": "MASQUE روی h3 با نویز firewall و اسکن balanced؛ شروع امن و سریع برای بیشتر شبکه‌ها.",
        "config": {
            "protocol": "masque",
            "scan_mode": "balanced",
            "ip_mode": "v4",
            "quick_reconnect": "on",
            "noise_profile": "firewall",
            "masque": {
                "transport": "h3",
                "fragment": False,
            },
        },
    },
    {
        "id": "udp-blocked",
        "label": "UDP بسته است",
        "description": "MASQUE روی h2/TCP؛ مناسب وقتی HTTP/3 یا QUIC وصل نمی‌شود.",
        "config": {
            "protocol": "masque",
            "scan_mode": "balanced",
            "ip_mode": "v4",
            "quick_reconnect": "on",
            "noise_profile": "firewall",
            "masque": {
                "transport": "h2",
                "fragment": False,
            },
        },
    },
    {
        "id": "strict-dpi",
        "label": "DPI سخت‌گیر",
        "description": "MASQUE روی h2 با fragmentation و نویز gfw برای شبکه‌های خیلی سخت‌گیر.",
        "config": {
            "protocol": "masque",
            "scan_mode": "ironclad",
            "ip_mode": "v4",
            "quick_reconnect": "on",
            "noise_profile": "gfw",
            "masque": {
                "transport": "h2",
                "fragment": True,
                "fragment_size": "8-24",
                "fragment_delay": "5-15",
            },
        },
    },
    {
        "id": "wg-fast",
        "label": "WireGuard سریع",
        "description": "برای شبکه‌های کمتر سخت‌گیر یا وقتی سرعت مهم‌تر از استتار است.",
        "config": {
            "protocol": "wg",
            "scan_mode": "balanced",
            "ip_mode": "v4",
            "quick_reconnect": "on",
            "noise_profile": "balanced",
            "wireguard": {
                "keepalive": "5",
                "no_profile_retry": False,
            },
        },
    },
    {
        "id": "gool-stability",
        "label": "GOOL پایدار",
        "description": "تونل دولایه برای وقتی که WireGuard معمولی وصل می‌شود اما ناپایدار است.",
        "config": {
            "protocol": "gool",
            "scan_mode": "thorough",
            "ip_mode": "v4",
            "quick_reconnect": "on",
            "noise_profile": "aggressive",
            "wireguard": {
                "keepalive": "5",
                "no_profile_retry": False,
            },
        },
    },
]


def merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge_dict(out[key], value)
        else:
            out[key] = value
    return out


def ensure_data_dir(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    if not path.exists():
        return dict(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return dict(default)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    cfg = merge_dict(DEFAULT_CONFIG, raw or {})

    cfg["bind_address"] = str(cfg.get("bind_address") or DEFAULT_CONFIG["bind_address"]).strip()
    cfg["protocol"] = str(cfg.get("protocol") or "masque").strip().lower()
    cfg["scan_mode"] = str(cfg.get("scan_mode") or "balanced").strip().lower()
    cfg["ip_mode"] = str(cfg.get("ip_mode") or "v4").strip().lower()
    cfg["quick_reconnect"] = str(cfg.get("quick_reconnect") or "ask").strip().lower()
    cfg["noise_profile"] = str(cfg.get("noise_profile") or "").strip()
    cfg["verbose"] = boolish(cfg.get("verbose"))
    cfg["peer"] = str(cfg.get("peer") or "").strip()
    cfg["wg_peer"] = str(cfg.get("wg_peer") or "").strip()

    masque = dict(cfg.get("masque") or {})
    cfg["masque"] = merge_dict(DEFAULT_CONFIG["masque"], masque)
    cfg["masque"]["transport"] = str(cfg["masque"].get("transport") or "h3").strip().lower()
    cfg["masque"]["h2_peer"] = str(cfg["masque"].get("h2_peer") or "").strip()
    cfg["masque"]["ech"] = str(cfg["masque"].get("ech") or "").strip()
    cfg["masque"]["fragment"] = boolish(cfg["masque"].get("fragment"))
    cfg["masque"]["fragment_size"] = str(cfg["masque"].get("fragment_size") or "").strip()
    cfg["masque"]["fragment_delay"] = str(cfg["masque"].get("fragment_delay") or "").strip()
    cfg["masque"]["validate_secs"] = str(cfg["masque"].get("validate_secs") or "").strip()
    cfg["masque"]["reconnect_secs"] = str(cfg["masque"].get("reconnect_secs") or "").strip()
    cfg["masque"]["no_data_check"] = boolish(cfg["masque"].get("no_data_check"))

    wireguard = dict(cfg.get("wireguard") or {})
    cfg["wireguard"] = merge_dict(DEFAULT_CONFIG["wireguard"], wireguard)
    cfg["wireguard"]["keepalive"] = str(cfg["wireguard"].get("keepalive") or "").strip()
    cfg["wireguard"]["reconnect_secs"] = str(cfg["wireguard"].get("reconnect_secs") or "").strip()
    cfg["wireguard"]["no_data_check"] = boolish(cfg["wireguard"].get("no_data_check"))
    cfg["wireguard"]["no_profile_retry"] = boolish(cfg["wireguard"].get("no_profile_retry"))

    config_paths = dict(cfg.get("config_paths") or {})
    cfg["config_paths"] = merge_dict(DEFAULT_CONFIG["config_paths"], config_paths)
    for key in ("base", "wg", "masque"):
        cfg["config_paths"][key] = str(cfg["config_paths"].get(key) or "").strip()

    advanced = dict(cfg.get("advanced") or {})
    cfg["advanced"] = merge_dict(DEFAULT_CONFIG["advanced"], advanced)
    cfg["advanced"]["binary_path"] = str(cfg["advanced"].get("binary_path") or DEFAULT_BINARY).strip()
    cfg["advanced"]["tls_groups"] = str(cfg["advanced"].get("tls_groups") or "").strip()
    cfg["advanced"]["extra_args"] = str(cfg["advanced"].get("extra_args") or "").strip()
    cfg["advanced"]["env_block"] = str(cfg["advanced"].get("env_block") or "").strip()

    return cfg


def load_config(data_dir: Path) -> Dict[str, Any]:
    cfg = read_json(data_dir / "config.json", DEFAULT_CONFIG)
    return normalize_config(cfg)


def save_config(data_dir: Path, cfg: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_config(cfg)
    write_json(data_dir / "config.json", normalized)
    return normalized


def read_state(data_dir: Path) -> Dict[str, Any]:
    state = read_json(data_dir / "state.json", {})
    if not isinstance(state, dict):
        state = {}
    return state


def save_state(data_dir: Path, state: Dict[str, Any]) -> None:
    write_json(data_dir / "state.json", state)


def is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def refresh_state(data_dir: Path) -> Dict[str, Any]:
    state = read_state(data_dir)
    pid = int(state.get("pid") or 0)
    if pid and not is_pid_running(pid):
        state["pid"] = None
        state["running"] = False
        state["last_exit_note"] = state.get("last_exit_note") or "process stopped"
        save_state(data_dir, state)
    else:
        state["running"] = bool(pid)
    return state


def human_duration(seconds: float | int | None) -> str:
    if not seconds:
        return "0s"
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def parse_env_block(block: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        env[key] = value
    return env


def append_flag(args: List[str], flag: str, value: str) -> None:
    if value:
        args.extend([flag, value])


def shell_join(parts: List[str]) -> str:
    try:
        return shlex.join(parts)
    except AttributeError:
        return " ".join(shlex.quote(p) for p in parts)


def build_launch_plan(cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg = normalize_config(cfg)
    args: List[str] = [cfg["advanced"]["binary_path"]]
    env: Dict[str, str] = {}

    append_flag(args, "--bind", cfg["bind_address"])

    quick = cfg["quick_reconnect"]
    if quick == "on":
        args.append("--quick-reconnect")
    elif quick == "off":
        args.append("--no-quick-reconnect")

    ip_mode = cfg["ip_mode"]
    if ip_mode == "v6":
        args.append("-6")
    elif ip_mode == "both":
        args.append("--dual")
    else:
        args.append("-4")

    append_flag(args, "--scan", cfg["scan_mode"])
    append_flag(args, "--peer", cfg["peer"])
    append_flag(args, "--wg-peer", cfg["wg_peer"])
    append_flag(args, "--noize", cfg["noise_profile"])

    protocol = cfg["protocol"]
    if protocol == "wg":
        args.append("--wg")
    elif protocol == "gool":
        args.append("--gool")
    else:
        args.append("--masque")

    if cfg["verbose"]:
        args.append("--verbose")

    for key, flag in (("base", "--config"), ("wg", "--wg-config"), ("masque", "--masque-config")):
        append_flag(args, flag, cfg["config_paths"].get(key, ""))

    append_flag(args, "--tls-groups", cfg["advanced"].get("tls_groups", ""))

    if protocol == "masque":
        masque = cfg["masque"]
        if masque["transport"] == "h2":
            args.append("--h2")
        append_flag(args, "--h2-peer", masque.get("h2_peer", ""))
        append_flag(args, "--ech", masque.get("ech", ""))
        if boolish(masque.get("no_data_check")):
            args.append("--no-data-check")
        append_flag(args, "--validate-secs", masque.get("validate_secs", ""))
        append_flag(args, "--reconnect-secs", masque.get("reconnect_secs", ""))
        if boolish(masque.get("fragment")) and masque.get("transport") == "h2":
            args.append("--fragment")
            append_flag(args, "--fragment-size", masque.get("fragment_size", ""))
            append_flag(args, "--fragment-delay", masque.get("fragment_delay", ""))
    else:
        wireguard = cfg["wireguard"]
        append_flag(args, "--keepalive", wireguard.get("keepalive", ""))
        if boolish(wireguard.get("no_data_check")):
            args.append("--no-data-check")
        if boolish(wireguard.get("no_profile_retry")):
            args.append("--no-profile-retry")
        if wireguard.get("reconnect_secs"):
            env["AETHER_WG_RECONNECT_SECS"] = wireguard["reconnect_secs"]

    extra_env = parse_env_block(cfg["advanced"].get("env_block", ""))
    env.update(extra_env)

    extra_args = cfg["advanced"].get("extra_args", "")
    if extra_args:
        args.extend(shlex.split(extra_args))

    env_preview = [f"{key}={value}" for key, value in sorted(env.items())]
    display_command = shell_join(args)
    if env_preview:
        display_command = " ".join(shell_join([item]) for item in env_preview) + " " + display_command

    return {
        "argv": args,
        "env": env,
        "env_preview": env_preview,
        "command_preview": display_command,
    }


def tail_file(path: Path, lines: int = 250) -> str:
    if not path.exists():
        return ""
    try:
        data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    return "\n".join(data[-max(1, min(lines, 2000)):])


def detect_urls(host: str, port: int) -> List[str]:
    urls: List[str] = []
    if host in {"127.0.0.1", "localhost", "::1"}:
        urls.append(f"http://127.0.0.1:{port}")
        urls.append(f"http://localhost:{port}")
        return urls

    urls.append(f"http://{host}:{port}")
    try:
        hostnames = socket.gethostbyname_ex(socket.gethostname())[2]
        for ip in hostnames:
            if ip and not ip.startswith("127."):
                urls.append(f"http://{ip}:{port}")
    except Exception:
        pass

    unique: List[str] = []
    for item in urls:
        if item not in unique:
            unique.append(item)
    return unique


def binary_info(cfg: Dict[str, Any]) -> Dict[str, Any]:
    binary_path = Path(cfg["advanced"]["binary_path"]).expanduser()
    info: Dict[str, Any] = {
        "path": str(binary_path),
        "exists": binary_path.exists(),
        "version": None,
    }
    if binary_path.exists():
        try:
            proc = subprocess.run(
                [str(binary_path), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
            output = (proc.stdout or "").strip()
            info["version"] = output
        except Exception as exc:
            info["version"] = f"error: {exc}"
    return info


def run_installer(action: str, data_dir: Path, extra: str = "") -> Dict[str, Any]:
    if not INSTALLER.exists():
        return {"ok": False, "message": f"installer not found: {INSTALLER}"}

    cmd = [str(INSTALLER), action]
    if extra:
        cmd.append(extra)
    env = os.environ.copy()
    env.setdefault("AETHER_WEB_DATA", str(data_dir))
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
            check=False,
            env=env,
            cwd=str(BASE_DIR),
        )
    except Exception as exc:
        return {"ok": False, "message": str(exc)}

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "output": proc.stdout,
    }


def start_process(cfg: Dict[str, Any], data_dir: Path) -> Dict[str, Any]:
    state = refresh_state(data_dir)
    if state.get("running") and state.get("pid"):
        return {"ok": False, "message": f"Aether already running with PID {state['pid']}"}

    plan = build_launch_plan(cfg)
    argv = plan["argv"]
    binary_path = Path(argv[0]).expanduser()
    if not binary_path.exists():
        return {
            "ok": False,
            "message": f"Aether binary not found at {binary_path}. First click install/update.",
            "plan": plan,
        }

    log_path = data_dir / "aether.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n===== [{timestamp}] starting Aether from web dashboard =====\n")

    env = os.environ.copy()
    env.update(plan["env"])
    try:
        log_handle = log_path.open("a", encoding="utf-8", buffering=1)
        proc = subprocess.Popen(
            [str(item) for item in argv],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            cwd=str(Path.home()),
            env=env,
            start_new_session=True,
        )
    except Exception as exc:
        return {"ok": False, "message": str(exc), "plan": plan}

    new_state = {
        "pid": proc.pid,
        "running": True,
        "started_at": int(time.time()),
        "command_preview": plan["command_preview"],
        "argv": argv,
        "env_preview": plan["env_preview"],
        "last_exit_note": None,
        "config_snapshot": cfg,
    }
    save_state(data_dir, new_state)
    return {"ok": True, "message": f"Aether started with PID {proc.pid}", "plan": plan, "state": new_state}


def stop_process(data_dir: Path) -> Dict[str, Any]:
    state = refresh_state(data_dir)
    pid = int(state.get("pid") or 0)
    if not pid:
        return {"ok": True, "message": "Aether is not running."}

    note = "stopped"
    try:
        os.killpg(pid, signal.SIGTERM)
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    deadline = time.time() + 8
    while time.time() < deadline:
        if not is_pid_running(pid):
            break
        time.sleep(0.25)

    if is_pid_running(pid):
        note = "force-killed"
        try:
            os.killpg(pid, signal.SIGKILL)
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        time.sleep(0.2)

    state["pid"] = None
    state["running"] = False
    state["last_exit_note"] = note
    state["stopped_at"] = int(time.time())
    save_state(data_dir, state)
    return {"ok": True, "message": f"Aether {note}."}


def restart_process(cfg: Dict[str, Any], data_dir: Path) -> Dict[str, Any]:
    stop_process(data_dir)
    time.sleep(0.5)
    return start_process(cfg, data_dir)


def build_status(cfg: Dict[str, Any], data_dir: Path, host: str, port: int) -> Dict[str, Any]:
    state = refresh_state(data_dir)
    plan = build_launch_plan(cfg)
    binary = binary_info(cfg)
    now = int(time.time())
    started_at = int(state.get("started_at") or 0)
    uptime_seconds = max(0, now - started_at) if state.get("running") and started_at else 0

    return {
        "app_title": APP_TITLE,
        "app_version": APP_VERSION,
        "running": bool(state.get("running") and state.get("pid")),
        "pid": state.get("pid"),
        "started_at": started_at or None,
        "uptime_seconds": uptime_seconds,
        "uptime_human": human_duration(uptime_seconds),
        "last_exit_note": state.get("last_exit_note"),
        "data_dir": str(data_dir),
        "log_file": str(data_dir / "aether.log"),
        "installer": str(INSTALLER),
        "binary": binary,
        "config": cfg,
        "defaults": DEFAULT_CONFIG,
        "presets": PRESETS,
        "command_preview": plan["command_preview"],
        "env_preview": plan["env_preview"],
        "urls": detect_urls(host, port),
        "active_config": state.get("config_snapshot"),
        "active_command": state.get("command_preview"),
        "host": host,
        "port": port,
        "server_time": now,
    }


def read_docs_index() -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not DOCS_DIR.exists():
        return out
    for path in sorted(DOCS_DIR.glob("*.md")):
        out.append({
            "name": path.name,
            "title": path.stem,
            "url": f"/docs/{path.name}",
        })
    return out


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "AetherTermuxWeb/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    @property
    def app(self) -> "AetherWebServer":
        return self.server  # type: ignore[return-value]

    def _json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _serve_file(self, path: Path, content_type: str | None = None) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        data = path.read_bytes()
        if content_type is None:
            if path.suffix == ".html":
                content_type = "text/html; charset=utf-8"
            elif path.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif path.suffix == ".js":
                content_type = "application/javascript; charset=utf-8"
            elif path.suffix == ".md":
                content_type = "text/markdown; charset=utf-8"
            elif path.suffix == ".json":
                content_type = "application/json; charset=utf-8"
            else:
                content_type = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            cfg = load_config(self.app.data_dir)
            payload = build_status(cfg, self.app.data_dir, self.app.host_addr, self.app.port_num)
            payload["docs"] = read_docs_index()
            self._json({"ok": True, "status": payload})
            return

        if path == "/api/config":
            cfg = load_config(self.app.data_dir)
            plan = build_launch_plan(cfg)
            self._json({"ok": True, "config": cfg, "plan": plan, "presets": PRESETS, "docs": read_docs_index()})
            return

        if path == "/api/logs":
            query = parse_qs(parsed.query or "")
            tail = int((query.get("tail") or ["250"])[0])
            text = tail_file(self.app.data_dir / "aether.log", tail)
            self._json({"ok": True, "log": text, "tail": tail})
            return

        if path == "/api/docs":
            self._json({"ok": True, "docs": read_docs_index()})
            return

        if path.startswith("/docs/"):
            safe = Path(path.removeprefix("/docs/")).name
            self._serve_file(DOCS_DIR / safe, "text/markdown; charset=utf-8")
            return

        if path == "/" or path == "":
            self._serve_file(STATIC_DIR / "index.html")
            return

        safe_path = Path(path.lstrip("/")).name
        candidate = STATIC_DIR / safe_path
        if candidate.exists() and candidate.is_file():
            self._serve_file(candidate)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/config":
            incoming = body.get("config") if isinstance(body, dict) else body
            cfg = save_config(self.app.data_dir, incoming or {})
            plan = build_launch_plan(cfg)
            self._json({"ok": True, "message": "Configuration saved.", "config": cfg, "plan": plan})
            return

        if path == "/api/start":
            cfg = body.get("config") if isinstance(body, dict) else None
            if cfg:
                save_config(self.app.data_dir, cfg)
            current = load_config(self.app.data_dir)
            result = start_process(current, self.app.data_dir)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/stop":
            result = stop_process(self.app.data_dir)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/restart":
            cfg = body.get("config") if isinstance(body, dict) else None
            if cfg:
                save_config(self.app.data_dir, cfg)
            current = load_config(self.app.data_dir)
            result = restart_process(current, self.app.data_dir)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/install":
            tag = str(body.get("tag") or "").strip() if isinstance(body, dict) else ""
            result = run_installer("install", self.app.data_dir, tag)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/update":
            result = run_installer("update", self.app.data_dir)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/uninstall":
            stop_process(self.app.data_dir)
            result = run_installer("uninstall", self.app.data_dir)
            self._json(result, 200 if result.get("ok") else 400)
            return

        if path == "/api/test":
            proxy = body.get("proxy") if isinstance(body, dict) else None
            proxy = str(proxy or load_config(self.app.data_dir).get("bind_address") or "127.0.0.1:1819")
            cmd = [
                "curl",
                "-sS",
                "-m",
                "12",
                "-x",
                f"socks5h://{proxy}",
                "https://www.cloudflare.com/cdn-cgi/trace",
            ]
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20, check=False)
                ok = proc.returncode == 0
                self._json({
                    "ok": ok,
                    "command": shell_join(cmd),
                    "output": proc.stdout,
                    "returncode": proc.returncode,
                }, 200 if ok else 400)
            except Exception as exc:
                self._json({"ok": False, "message": str(exc), "command": shell_join(cmd)}, 400)
            return

        self._json({"ok": False, "message": "Unknown endpoint."}, 404)


class AetherWebServer(ThreadingHTTPServer):
    def __init__(self, host_addr: str, port_num: int, data_dir: Path):
        self.host_addr = host_addr
        self.port_num = port_num
        self.data_dir = data_dir
        super().__init__((host_addr, port_num), ApiHandler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aether Termux Web")
    parser.add_argument("--host", default=os.environ.get("AETHER_WEB_HOST", "127.0.0.1"), help="bind address for the dashboard (default: 127.0.0.1)")
    parser.add_argument("--port", default=int(os.environ.get("AETHER_WEB_PORT", "8787")), type=int, help="bind port for the dashboard (default: 8787)")
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR), help="directory used for config/state/log files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir).expanduser()
    ensure_data_dir(data_dir)
    save_config(data_dir, load_config(data_dir))

    server = AetherWebServer(args.host, args.port, data_dir)
    print(f"{APP_TITLE} {APP_VERSION}")
    for url in detect_urls(args.host, args.port):
        print(f"Open: {url}")
    print(f"Data: {data_dir}")
    print("Press Ctrl+C to stop the web dashboard.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
