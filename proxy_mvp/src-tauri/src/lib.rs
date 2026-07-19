use std::sync::Mutex;
use std::process::{Child, Command};
use tauri::State;
use tauri::Manager;

// ─── State ───────────────────────────────────────────────
struct ProxyState(Mutex<Option<Child>>);

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
            .create_subkey(
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            .map_err(|e| format!("Registry open error: {}", e))?;

        if enabled {
            key.set_value("ProxyEnable", &1u32)
                .map_err(|e| format!("ProxyEnable write error: {}", e))?;
            key.set_value("ProxyServer", &"localhost:8080")
                .map_err(|e| format!("ProxyServer write error: {}", e))?;
        } else {
            key.set_value("ProxyEnable", &0u32)
                .map_err(|e| format!("ProxyEnable clear error: {}", e))?;
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
            return Err(format!(
                "CA cert not found at {}. Run mitmdump once to generate it.",
                cert_path.display()
            ));
        }

        let output = Command::new("certutil")
            .args(["-addstore", "-user", "Root"])
            .arg(cert_path.to_str().unwrap_or(""))
            .output()
            .map_err(|e| format!("certutil failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_api {
    pub fn set_proxy_registry(_enabled: bool) -> Result<(), String> {
        Err("System proxy toggle is Windows-only for MVP".into())
    }
    pub fn install_ca_cert() -> Result<String, String> {
        Err("CA cert auto-install is Windows-only for MVP".into())
    }
}

// ─── Tauri Commands ──────────────────────────────────────

#[tauri::command]
fn toggle_proxy(app: tauri::AppHandle, state: State<ProxyState>, on: bool) -> Result<String, String> {
    let mut guard = state.0.lock().map_err(|e| e.to_string())?;

    if on {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }

        let addon = resolve_addon_path(&app);
        let child = Command::new("mitmdump")
            .args(["--listen-port", "8080", "-s"])
            .arg(&addon)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!(
                "Failed to start mitmdump: {}. Addon at: {}",
                e, addon
            ))?;

        *guard = Some(child);
        windows_api::set_proxy_registry(true)?;

        Ok("Proxy ON — monitoring ChatGPT + Claude".into())
    } else {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }
        windows_api::set_proxy_registry(false)?;

        Ok("Proxy OFF".into())
    }
}

#[tauri::command]
fn get_proxy_status(state: State<ProxyState>) -> Result<bool, String> {
    let guard = state.0.lock().map_err(|e| e.to_string())?;
    Ok(guard.is_some())
}

#[tauri::command]
fn install_cert() -> Result<String, String> {
    windows_api::install_ca_cert()
}

fn resolve_addon_path(app: &tauri::AppHandle) -> String {
    // 1. Attempt to resolve from Tauri resource bundle (production)
    let resource_path = app
        .path()
        .resource_dir()
        .unwrap_or_default()
        .join("pii_redact.py");
    if resource_path.exists() {
        return resource_path.to_string_lossy().to_string();
    }

    // 2. Check common dev paths
    let candidates = [
        std::path::PathBuf::from("C:\\proxy-app\\pii_redact.py"),
        std::path::PathBuf::from("pii_redact.py"),
    ];
    for p in &candidates {
        if p.exists() {
            return p.to_string_lossy().to_string();
        }
    }

    // 3. Fallback — return so the user sees a clear error
    candidates[1].to_string_lossy().to_string()
}

// ─── Entry Point ─────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ProxyState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            toggle_proxy,
            get_proxy_status,
            install_cert,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
