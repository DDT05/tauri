use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::{Manager, State};

// ─── Canonical app data directory ─────────────────────────
// Everything lives under %LOCALAPPDATA%\hebed-proxy\
// - pii_redact.py (extracted from bundle on first run)
// - proxy.log / proxy.err (mitmdump stdout/stderr)
// - pii_events.log (addon's structured log)

fn app_data_dir() -> PathBuf {
    let local = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("AppData").join("Local")
        });
    local.join("hebed-proxy")
}

// ─── State ───────────────────────────────────────────────
struct ProxyState {
    child: Mutex<Option<Child>>,
    addon_path: Mutex<String>,
    mitmdump_path: Mutex<String>,
}

// ─── Windows-specific ────────────────────────────────────
#[cfg(target_os = "windows")]
mod windows_api {
    use std::path::PathBuf;
    use std::process::Command;

    pub fn broadcast_proxy_change() {
        unsafe {
            let user32 = libloading::Library::new("user32.dll").unwrap();
            let send_msg: libloading::Symbol<
                unsafe extern "system" fn(isize, u32, usize, *const u16, u32, u32, *mut u32) -> isize,
            > = user32.get(b"SendMessageTimeoutW").unwrap();
            let msg: Vec<u16> =
                "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\0"
                    .encode_utf16()
                    .collect();
            send_msg(0xFFFF, 0x001A, 0, msg.as_ptr(), 0, 5000, std::ptr::null_mut());

            let wininet = libloading::Library::new("wininet.dll").unwrap();
            let set_option: libloading::Symbol<
                unsafe extern "system" fn(isize, u32, *const u8, u32) -> i32,
            > = wininet.get(b"InternetSetOptionW").unwrap();
            set_option(0, 39, std::ptr::null(), 0);
            set_option(0, 37, std::ptr::null(), 0);
        }
    }

    pub fn set_proxy_registry(enabled: bool) -> Result<(), String> {
        use winreg::enums::*;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _disp) = hkcu
            .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .map_err(|e| format!("Registry error: {}", e))?;
        if enabled {
            key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
            key.set_value("ProxyServer", &"localhost:8080").map_err(|e| e.to_string())?;
        } else {
            key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        }
        broadcast_proxy_change();
        Ok(())
    }

    pub fn install_ca_cert() -> Result<String, String> {
        let cert_path = dirs::home_dir()
            .ok_or("Cannot find home directory")?
            .join(".mitmproxy")
            .join("mitmproxy-ca-cert.cer");
        if !cert_path.exists() {
            return Err(format!("CA cert not found at {}. Start proxy once to generate it.", cert_path.display()));
        }
        let output = Command::new("certutil")
            .args(["-addstore", "-user", "Root"])
            .arg(cert_path.to_str().unwrap_or(""))
            .output()
            .map_err(|e| format!("certutil failed: {}", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_api {
    pub fn set_proxy_registry(_: bool) -> Result<(), String> { Err("Windows-only".into()) }
    pub fn install_ca_cert() -> Result<String, String> { Err("Windows-only".into()) }
    pub fn broadcast_proxy_change() {}
}

// ─── mitmdump discovery ──────────────────────────────────

fn find_mitmdump() -> Option<String> {
    // Search common install locations (no hardcoded user paths)
    let candidates = [
        // winget / Microsoft Store shim (most common)
        r"C:\Users",  // we'll search specifically below
    ];

    // Check PATH first
    if let Ok(output) = std::process::Command::new("where").arg("mitmdump").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let p = line.trim();
            if !p.is_empty() && std::path::Path::new(p).exists() {
                return Some(p.to_string());
            }
        }
    }

    // Search WindowsApps (winget install location)
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let base = std::path::Path::new(&local)
            .join("Microsoft")
            .join("WindowsApps");
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let p = entry.path().join("mitmdump.exe");
                if p.exists() {
                    return Some(p.to_string_lossy().to_string());
                }
            }
        }
    }

    // Fallback: try unqualified (will work if in PATH)
    Some("mitmdump".to_string())
}

// ─── First-run resource extraction ────────────────────────

fn ensure_addon_extracted(app: &tauri::AppHandle) -> String {
    let dest = app_data_dir().join("pii_redact.py");

    // Already extracted
    if dest.exists() {
        return dest.to_string_lossy().to_string();
    }

    // Try to copy from bundled resource
    if let Ok(res) = app.path().resource_dir() {
        let src = res.join("pii_redact.py");
        if src.exists() {
            fs::create_dir_all(app_data_dir()).ok();
            if fs::copy(&src, &dest).is_ok() {
                return dest.to_string_lossy().to_string();
            }
        }
    }

    // Dev mode fallbacks — search project root and exe directory
    for search_dir in [
        std::env::current_dir().ok(),
        std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())),
    ].iter().flatten() {
        let p = search_dir.join("pii_redact.py");
        if p.exists() {
            // Copy to app data so it persists
            fs::create_dir_all(app_data_dir()).ok();
            let _ = fs::copy(&p, &dest);
            return p.to_string_lossy().to_string();
        }
    }

    // Last resort — return app data path, let mitmdump report the error
    dest.to_string_lossy().to_string()
}

fn ensure_log_dir() -> std::io::Result<PathBuf> {
    let dir = app_data_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ─── Tauri Commands ──────────────────────────────────────

#[tauri::command]
fn toggle_proxy(
    app: tauri::AppHandle,
    state: State<ProxyState>,
    on: bool,
) -> Result<String, String> {
    let mut guard = state.child.lock().map_err(|e| e.to_string())?;

    if on {
        // Kill any existing instance
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }

        // Resolve paths
        let addon = ensure_addon_extracted(&app);
        *state.addon_path.lock().unwrap() = addon.clone();

        let mitmdump = state.mitmdump_path.lock().unwrap().clone();
        let mitmdump = if mitmdump.is_empty() {
            find_mitmdump().unwrap_or_else(|| "mitmdump".to_string())
        } else {
            mitmdump
        };

        let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
        let log_file = log_dir.join("proxy.log");
        let err_file = log_dir.join("proxy.err");

        let out = fs::File::create(&log_file).map_err(|e| e.to_string())?;
        let err = fs::File::create(&err_file).map_err(|e| e.to_string())?;

        let child = Command::new(&mitmdump)
            .args(["--listen-port", "8080", "-s"])
            .arg(&addon)
            .stdout(std::process::Stdio::from(out))
            .stderr(std::process::Stdio::from(err))
            .spawn()
            .map_err(|e| format!(
                "mitmdump not found.\n\nTried: {}\n\nInstall mitmproxy from https://mitmproxy.org",
                mitmdump
            ))?;

        *guard = Some(child);

        // Wait briefly and check it didn't crash immediately
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let check = guard.as_mut().unwrap();
        match check.try_wait() {
            Ok(Some(_status)) => {
                let err_text = fs::read_to_string(&err_file).unwrap_or_default();
                *guard = None;
                return Err(format!("mitmdump crashed.\nAddon: {}\n{}", addon, err_text));
            }
            Ok(None) => {} // Still running
            Err(e) => return Err(format!("mitmdump status check failed: {}", e)),
        }

        windows_api::set_proxy_registry(true)?;

        Ok(format!("Proxy ON\nLog: {}", log_file.display()))
    } else {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }
        windows_api::set_proxy_registry(false)?;
        Ok("Proxy OFF".into())
    }
}

#[tauri::command]
fn get_proxy_status(state: State<ProxyState>) -> Result<serde_json::Value, String> {
    let guard = state.child.lock().map_err(|e| e.to_string())?;
    let running = match guard.as_ref() {
        Some(child) => {
            let pid = child.id();
            check_process_alive(pid)
        }
        None => false,
    };

    Ok(serde_json::json!({
        "running": running,
        "port_listening": port_8080_listening(),
        "addon": state.addon_path.lock().unwrap().clone(),
    }))
}

#[tauri::command]
fn get_logs() -> Result<String, String> {
    let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;

    // 1. PII events log (structured, from addon's _log())
    let pii_file = log_dir.join("pii_events.log");
    if pii_file.exists() {
        let pii = fs::read_to_string(&pii_file).unwrap_or_default();
        if !pii.trim().is_empty() {
            return Ok(format!("=== PII Events ===\n{}", pii));
        }
    }

    // 2. Fallback: mitmdump stdout
    let log_file = log_dir.join("proxy.log");
    if log_file.exists() {
        let mut output = String::from("=== mitmdump stdout ===\n");
        let f = fs::File::open(&log_file).map_err(|e| e.to_string())?;
        for line in BufReader::new(f).lines().flatten() {
            if line.contains("[PII]") || line.contains("error") || line.contains("Error") || line.contains("listening") {
                output.push_str(&line);
                output.push('\n');
            }
        }
        if output != "=== mitmdump stdout ===\n" {
            let err_file = log_dir.join("proxy.err");
            if err_file.exists() {
                let err = fs::read_to_string(&err_file).unwrap_or_default();
                if !err.trim().is_empty() {
                    output.push_str("\n=== mitmdump stderr ===\n");
                    output.push_str(&err);
                }
            }
            return Ok(output);
        }
    }

    Ok("No PII events yet. Open ChatGPT and send a message containing an email or phone number.".into())
}

#[tauri::command]
fn install_cert() -> Result<String, String> {
    windows_api::install_ca_cert()
}

fn port_8080_listening() -> bool {
    std::net::TcpStream::connect("127.0.0.1:8080").is_ok()
}

#[cfg(target_os = "windows")]
fn check_process_alive(pid: u32) -> bool {
    unsafe {
        let kernel32 = match libloading::Library::new("kernel32.dll") {
            Ok(l) => l,
            Err(_) => return false,
        };
        let open: libloading::Symbol<unsafe extern "system" fn(u32, i32, u32) -> isize> =
            match kernel32.get(b"OpenProcess") {
                Ok(f) => f,
                Err(_) => return false,
            };
        let h = open(0x100000, 0, pid);
        if h == 0 {
            return false;
        }
        let wait: libloading::Symbol<unsafe extern "system" fn(isize, u32) -> u32> =
            match kernel32.get(b"WaitForSingleObject") {
                Ok(f) => f,
                Err(_) => return false,
            };
        let result = wait(h, 0);
        let close: libloading::Symbol<unsafe extern "system" fn(isize) -> i32> =
            kernel32.get(b"CloseHandle").unwrap();
        close(h);
        result != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn check_process_alive(_pid: u32) -> bool {
    true
}

// ─── Entry Point ─────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // On first launch, extract bundled resources to app data
            let handle = app.handle().clone();
            let _ = ensure_addon_extracted(&handle);
            Ok(())
        })
        .manage(ProxyState {
            child: Mutex::new(None),
            addon_path: Mutex::new(String::new()),
            mitmdump_path: Mutex::new(String::new()),
        })
        .invoke_handler(tauri::generate_handler![
            toggle_proxy,
            get_proxy_status,
            get_logs,
            install_cert,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
