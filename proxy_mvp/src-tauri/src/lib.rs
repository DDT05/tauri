use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use tauri::{Manager, State};

// ─── State ───────────────────────────────────────────────
struct ProxyState {
    child: Mutex<Option<Child>>,
    addon_path: Mutex<String>,
}

// ─── Windows-specific ────────────────────────────────────
#[cfg(target_os = "windows")]
mod windows_api {
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

    pub fn log_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("hebed-proxy")
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_api {
    use std::path::PathBuf;
    pub fn set_proxy_registry(_: bool) -> Result<(), String> { Err("Windows-only".into()) }
    pub fn install_ca_cert() -> Result<String, String> { Err("Windows-only".into()) }
    pub fn log_dir() -> PathBuf { PathBuf::from("/tmp/hebed-proxy") }
}

// ─── Helpers ─────────────────────────────────────────────

fn resolve_addon_path(app: &tauri::AppHandle) -> String {
    // 1. Tauri bundled resource (production)
    if let Ok(res) = app.path().resource_dir() {
        let p = res.join("pii_redact.py");
        if p.exists() {
            return p.to_string_lossy().to_string();
        }
    }
    // 2. Same directory as the executable (dev mode)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("pii_redact.py");
            if p.exists() {
                return p.to_string_lossy().to_string();
            }
        }
    }
    // 3. Common locations
    for p in [r"C:\proxy-app\pii_redact.py", r"pii_redact.py"] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    // 4. Fallback — return bundle path so error message is clear
    app.path()
        .resource_dir()
        .unwrap_or_default()
        .join("pii_redact.py")
        .to_string_lossy()
        .to_string()
}

fn ensure_log_dir() -> std::io::Result<PathBuf> {
    let dir = windows_api::log_dir();
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
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }

        let addon = resolve_addon_path(&app);
        *state.addon_path.lock().unwrap() = addon.clone();

        // Log file for mitmdump output
        let log_dir = ensure_log_dir().map_err(|e| e.to_string())?;
        let log_file = log_dir.join("proxy.log");
        let err_file = log_dir.join("proxy.err");

        let out = fs::File::create(&log_file).map_err(|e| e.to_string())?;
        let err = fs::File::create(&err_file).map_err(|e| e.to_string())?;

        let child = Command::new("mitmdump")
            .args(["--listen-port", "8080", "-s"])
            .arg(&addon)
            .stdout(std::process::Stdio::from(out))
            .stderr(std::process::Stdio::from(err))
            .spawn()
            .map_err(|e| format!(
                "mitmdump not found. Install it: winget install mitmproxy\nError: {}",
                e
            ))?;

        *guard = Some(child);

        // Wait briefly and check it didn't crash immediately
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let mut check = guard.as_ref().unwrap();
        match check.try_wait() {
            Ok(Some(status)) => {
                // Crashed — read error log
                let err_text = fs::read_to_string(&err_file).unwrap_or_default();
                *guard = None;
                return Err(format!("mitmdump crashed.\nAddon: {}\n{}", addon, err_text));
            }
            Ok(None) => {} // Still running — good
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
            // Check if the process is still alive
            if let Ok(mut proc) = unsafe {
                let id = child.id();
                if let Some(id) = id {
                    let h = libloading::Library::new("kernel32.dll")
                        .ok()
                        .and_then(|lib| {
                            unsafe {
                                let open: libloading::Symbol<
                                    unsafe extern "system" fn(u32, i32, u32) -> isize,
                                > = lib.get(b"OpenProcess").ok()?;
                                let h = open(0x400, 0, id);
                                if h == 0 { None } else { Some(h) }
                            }
                        });
                    h
                } else {
                    None
                }
            } {
                true // process exists
            } else {
                false
            }
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
    let log_file = log_dir.join("proxy.log");
    let err_file = log_dir.join("proxy.err");

    let mut output = String::new();

    if log_file.exists() {
        output.push_str("=== mitmdump stdout ===\n");
        let f = fs::File::open(&log_file).map_err(|e| e.to_string())?;
        for line in BufReader::new(f).lines().flatten() {
            // Show only PII-related and important lines
            if line.contains("[PII]") || line.contains("error") || line.contains("Error") || line.contains("listening") {
                output.push_str(&line);
                output.push('\n');
            }
        }
    }

    if err_file.exists() {
        let err = fs::read_to_string(&err_file).unwrap_or_default();
        if !err.trim().is_empty() {
            output.push_str("\n=== mitmdump stderr ===\n");
            output.push_str(&err);
        }
    }

    if output.is_empty() {
        Ok("No logs yet. Send a prompt in ChatGPT with an email or phone number.".into())
    } else {
        Ok(output)
    }
}

#[tauri::command]
fn install_cert() -> Result<String, String> {
    windows_api::install_ca_cert()
}

fn port_8080_listening() -> bool {
    std::net::TcpStream::connect("127.0.0.1:8080").is_ok()
}

// ─── Entry Point ─────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ProxyState {
            child: Mutex::new(None),
            addon_path: Mutex::new(String::new()),
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
