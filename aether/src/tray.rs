//! Windows-only "close to tray" support.
//!
//! Aether is a console application. On Windows, clicking the X on the console
//! window sends `CTRL_CLOSE_EVENT`, after which the system force-terminates
//! the process — taking the tunnel down with it. This module instead detaches
//! the process from its console so the tunnel keeps running in the background,
//! and puts a tray icon with an "Exit" item in the notification area so the
//! user can still quit cleanly afterwards.
//!
//! The whole feature can be disabled with `AETHER_CLOSE_TO_TRAY=0`.

use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};

extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    fn FreeConsole() -> i32;
}

const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;
const CTRL_CLOSE_EVENT: u32 = 2;
const CTRL_LOGOFF_EVENT: u32 = 5;
const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// Initializes close-to-tray. Best-effort: every failure is logged and ignored
/// so the app behaves exactly as before on machines where the tray cannot be
/// created (headless sessions, locked-down shells, ...).
pub fn init() {
    if !enabled() {
        return;
    }
    if let Err(e) = install_console_handler() {
        log::warn!("[close-to-tray] console handler install failed: {e}");
    }
    if let Err(e) = spawn_tray() {
        log::warn!("[close-to-tray] tray unavailable: {e}");
    }
}

fn enabled() -> bool {
    std::env::var("AETHER_CLOSE_TO_TRAY")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            )
        })
        .unwrap_or(true)
}

unsafe extern "system" fn console_handler(ctrl_type: u32) -> i32 {
    match ctrl_type {
        // The console window was closed (X) or the session is ending: detach
        // from the console and keep the tunnel alive in the background.
        // Detaching removes this process from the console's process list, so
        // the ~5s force-termination that follows a close event no longer
        // applies to us.
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            let _ = FreeConsole();
            1 // TRUE: event handled
        }
        // Leave Ctrl+C / Ctrl+Break to the default handler so interactive
        // shutdown behaviour is unchanged.
        CTRL_C_EVENT | CTRL_BREAK_EVENT => 0,
        _ => 0,
    }
}

fn install_console_handler() -> std::io::Result<()> {
    // SAFETY: the handler has no payload and stays valid for the process
    // lifetime; it is never unregistered.
    let rc = unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) };
    if rc == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn spawn_tray() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let menu = Menu::new();
    let exit = MenuItem::new("Exit", true, None);
    // Get exit_id BEFORE menu.append so we don't need to borrow exit afterwards.
    let exit_id = exit.id();
    menu.append(&exit)?;

    let icon = Icon::from_rgba(app_icon(), 32, 32)?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Aether")
        .with_icon(icon)
        .build()?;

    // Menu keeps exit alive; tray must stay alive for process lifetime.
    std::mem::forget(tray);

    let receiver = MenuEvent::receiver();
    std::thread::spawn(move || loop {
        if let Ok(event) = receiver.try_recv() {
            if event.id() == exit_id {
                std::process::exit(0);
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    });

    log::info!(
        "[+] close-to-tray enabled: closing the window keeps Aether running in the background"
    );
    Ok(())
}

/// 32x32 RGBA tray icon: a cyan "A" on a dark slate background, drawn from a
/// tiny bitmap so the module needs no image-processing dependency.
fn app_icon() -> Vec<u8> {
    const SIZE: usize = 32;
    const GLYPH: [[u8; 5]; 7] = [
        [0, 0, 1, 0, 0],
        [0, 1, 0, 1, 0],
        [0, 1, 0, 1, 0],
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 0, 0, 0, 1],
        [1, 0, 0, 0, 1],
    ];
    const BG: (u8, u8, u8, u8) = (30, 41, 59, 255); // slate-800
    const FG: (u8, u8, u8, u8) = (34, 211, 238, 255); // cyan-400
    const OX: usize = 13;
    const OY: usize = 6;

    let mut px = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let on = x >= OX
                && x < OX + GLYPH[0].len()
                && y >= OY
                && y < OY + GLYPH.len()
                && GLYPH[y - OY][x - OX] == 1;
            let (r, g, b, a) = if on { FG } else { BG };
            let i = (y * SIZE + x) * 4;
            px[i] = r;
            px[i + 1] = g;
            px[i + 2] = b;
            px[i + 3] = a;
        }
    }
    px
}
