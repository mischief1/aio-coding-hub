//! Usage: Windows WSL related Tauri commands.

use crate::app_state::{ensure_db_ready, DbInitState, GatewayState};
#[cfg(windows)]
use crate::db;
use crate::shared::mutex_ext::MutexExt;
use crate::{blocking, gateway, settings, wsl};
#[cfg(windows)]
use tauri::Emitter;
use tauri::Manager;

#[tauri::command]
pub(crate) async fn wsl_detect() -> wsl::WslDetection {
    blocking::run(
        "wsl_detect",
        move || -> crate::shared::error::AppResult<wsl::WslDetection> { Ok(wsl::detect()) },
    )
    .await
    .unwrap_or(wsl::WslDetection {
        detected: false,
        distros: Vec::new(),
    })
}

#[tauri::command]
pub(crate) async fn wsl_host_address_get() -> Option<String> {
    blocking::run(
        "wsl_host_address_get",
        move || -> crate::shared::error::AppResult<Option<String>> {
            Ok(wsl::host_ipv4_best_effort())
        },
    )
    .await
    .unwrap_or(None)
}

#[tauri::command]
pub(crate) async fn wsl_config_status_get(
    distros: Option<Vec<String>>,
) -> Vec<wsl::WslDistroConfigStatus> {
    blocking::run(
        "wsl_config_status_get",
        move || -> crate::shared::error::AppResult<Vec<wsl::WslDistroConfigStatus>> {
            let distros = match distros {
                Some(v) if v.is_empty() => return Ok(Vec::new()),
                Some(v) if !v.is_empty() => v,
                _ => {
                    let detection = wsl::detect();
                    if !detection.detected || detection.distros.is_empty() {
                        return Ok(Vec::new());
                    }
                    detection.distros
                }
            };

            Ok(wsl::get_config_status(&distros))
        },
    )
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub(crate) async fn wsl_configure_clients(
    app: tauri::AppHandle,
    db_state: tauri::State<'_, DbInitState>,
) -> Result<wsl::WslConfigureReport, String> {
    if !cfg!(windows) {
        return Ok(wsl::WslConfigureReport {
            ok: false,
            message: "WSL configuration is only available on Windows".to_string(),
            distros: Vec::new(),
        });
    }

    let db = ensure_db_ready(app.clone(), db_state.inner()).await?;

    let cfg = blocking::run("wsl_configure_clients_read_settings", {
        let app = app.clone();
        move || -> crate::shared::error::AppResult<settings::AppSettings> {
            Ok(settings::read(&app).unwrap_or_default())
        }
    })
    .await?;

    if cfg.gateway_listen_mode == settings::GatewayListenMode::Localhost {
        return Ok(wsl::WslConfigureReport {
            ok: false,
            message: "监听模式为“仅本地(127.0.0.1)”时，WSL 无法访问网关。请先切换到：WSL 自动检测 / 局域网 / 自定义地址。".to_string(),
            distros: Vec::new(),
        });
    }

    let detection = wsl::detect();
    if !detection.detected || detection.distros.is_empty() {
        return Ok(wsl::WslConfigureReport {
            ok: false,
            message: "WSL not detected".to_string(),
            distros: Vec::new(),
        });
    }

    let preferred_port = cfg.preferred_port;
    let status = blocking::run("wsl_configure_clients_ensure_gateway", {
        let app = app.clone();
        let db = db.clone();
        move || {
            let state = app.state::<GatewayState>();
            let mut manager = state.0.lock_or_recover();
            manager.start(&app, db, Some(preferred_port))
        }
    })
    .await?;

    let port = status
        .port
        .ok_or_else(|| "gateway_start returned no port".to_string())?;

    let host = match cfg.gateway_listen_mode {
        settings::GatewayListenMode::Localhost => "127.0.0.1".to_string(),
        settings::GatewayListenMode::WslAuto | settings::GatewayListenMode::Lan => {
            wsl::resolve_wsl_host(&cfg)
        }
        settings::GatewayListenMode::Custom => {
            let parsed = match gateway::listen::parse_custom_listen_address(
                &cfg.gateway_custom_listen_address,
            ) {
                Ok(v) => v,
                Err(err) => {
                    return Ok(wsl::WslConfigureReport {
                        ok: false,
                        message: format!("自定义监听地址无效：{err}"),
                        distros: Vec::new(),
                    });
                }
            };
            if gateway::listen::is_wildcard_host(&parsed.host) {
                wsl::resolve_wsl_host(&cfg)
            } else {
                parsed.host
            }
        }
    };

    let proxy_origin = format!("http://{}", gateway::listen::format_host_port(&host, port));
    let distros = detection.distros;
    let targets = cfg.wsl_target_cli;

    // Gather MCP and Prompt sync data from DB
    let (mcp_data, prompt_data) = blocking::run("wsl_configure_gather_sync_data", {
        let db = db.clone();
        move || -> crate::shared::error::AppResult<(wsl::WslMcpSyncData, wsl::WslPromptSyncData)> {
            let conn = db.open_connection()?;
            let mcp = wsl::gather_mcp_sync_data(&conn)?;
            let prompts = wsl::gather_prompt_sync_data(&conn)?;
            Ok((mcp, prompts))
        }
    })
    .await?;

    let app_for_sync = app.clone();
    let report = blocking::run(
        "wsl_configure_clients",
        move || -> crate::shared::error::AppResult<wsl::WslConfigureReport> {
            Ok(wsl::configure_clients(
                &app_for_sync,
                &distros,
                &targets,
                &proxy_origin,
                Some(&mcp_data),
                Some(&prompt_data),
            ))
        },
    )
    .await?;

    Ok(report)
}

/// Core WSL auto-sync logic shared by settings-change sync and MCP/Prompt-change sync.
/// Checks preconditions (wsl_auto_config enabled, listen mode != Localhost),
/// detects WSL, resolves host, gathers sync data, and configures CLI clients.
#[cfg(windows)]
pub(crate) async fn wsl_auto_sync_core(app: &tauri::AppHandle) -> Result<(), String> {
    use crate::app_state::{ensure_db_ready, DbInitState, GatewayState};
    use crate::shared::mutex_ext::MutexExt;

    // 1. Read settings and check preconditions
    let cfg = blocking::run("wsl_core_read_settings", {
        let app = app.clone();
        move || -> crate::shared::error::AppResult<settings::AppSettings> {
            Ok(settings::read(&app).unwrap_or_default())
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    if !cfg.wsl_auto_config {
        tracing::debug!("WSL auto-sync core: wsl_auto_config disabled, skipping");
        return Ok(());
    }

    if cfg.gateway_listen_mode == settings::GatewayListenMode::Localhost {
        tracing::debug!("WSL auto-sync core: listen mode is localhost, skipping");
        return Ok(());
    }

    // 2. Get gateway port
    let port = {
        let state = app.state::<GatewayState>();
        let manager = state.0.lock_or_recover();
        let status = manager.status();
        match status.port {
            Some(p) => p,
            None => {
                tracing::debug!("WSL auto-sync core: gateway not running, skipping");
                return Ok(());
            }
        }
    };

    // 3. Detect WSL
    let detection = blocking::run(
        "wsl_core_detect",
        || -> crate::shared::error::AppResult<wsl::WslDetection> { Ok(wsl::detect()) },
    )
    .await
    .map_err(|e| e.to_string())?;

    if !detection.detected || detection.distros.is_empty() {
        tracing::debug!("WSL auto-sync core: no WSL environment detected, skipping");
        return Ok(());
    }

    // 4. Resolve host
    let host = match cfg.gateway_listen_mode {
        settings::GatewayListenMode::Localhost => "127.0.0.1".to_string(),
        settings::GatewayListenMode::WslAuto | settings::GatewayListenMode::Lan => {
            wsl::resolve_wsl_host(&cfg)
        }
        settings::GatewayListenMode::Custom => {
            let parsed =
                gateway::listen::parse_custom_listen_address(&cfg.gateway_custom_listen_address)
                    .map_err(|e| format!("invalid custom listen address: {e}"))?;
            if gateway::listen::is_wildcard_host(&parsed.host) {
                wsl::resolve_wsl_host(&cfg)
            } else {
                parsed.host
            }
        }
    };

    let proxy_origin = format!("http://{}", gateway::listen::format_host_port(&host, port));
    let targets = cfg.wsl_target_cli;
    let distros = detection.distros;

    // 5. Gather MCP and Prompt sync data
    let db_state = app.state::<DbInitState>();
    let db = ensure_db_ready(app.clone(), db_state.inner()).await?;

    let (mcp_data, prompt_data) = blocking::run("wsl_core_gather_sync_data", {
        let db = db.clone();
        move || -> crate::shared::error::AppResult<(wsl::WslMcpSyncData, wsl::WslPromptSyncData)> {
            let conn = db.open_connection()?;
            let mcp = wsl::gather_mcp_sync_data(&conn)?;
            let prompts = wsl::gather_prompt_sync_data(&conn)?;
            Ok((mcp, prompts))
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    // 6. Configure clients
    let app_for_sync = app.clone();
    let report = blocking::run(
        "wsl_core_configure",
        move || -> crate::shared::error::AppResult<wsl::WslConfigureReport> {
            Ok(wsl::configure_clients(
                &app_for_sync,
                &distros,
                &targets,
                &proxy_origin,
                Some(&mcp_data),
                Some(&prompt_data),
            ))
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    tracing::info!(
        ok = report.ok,
        message = %report.message,
        "WSL auto-sync core completed"
    );

    let _ = app.emit("wsl:auto_config_result", &report);

    Ok(())
}

/// Debounced WSL sync trigger for MCP/Prompt changes.
/// Uses a background task with 500ms debounce window to coalesce rapid changes.
#[cfg(windows)]
pub(crate) mod wsl_sync_trigger {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::sync::Notify;

    static TRIGGER_NOTIFY: OnceLock<Notify> = OnceLock::new();
    static TASK_SPAWNED: AtomicBool = AtomicBool::new(false);

    fn trigger_notify() -> &'static Notify {
        TRIGGER_NOTIFY.get_or_init(Notify::new)
    }

    /// Fire-and-forget trigger. Notifies the background debounce task to schedule a WSL sync.
    /// If the background task hasn't been spawned yet, it will be spawned on first call.
    pub(crate) fn trigger(app: tauri::AppHandle) {
        if !TASK_SPAWNED.swap(true, Ordering::SeqCst) {
            tauri::async_runtime::spawn(debounce_loop(app));
        }
        trigger_notify().notify_one();
    }

    async fn debounce_loop(app: tauri::AppHandle) {
        const DEBOUNCE: Duration = Duration::from_millis(500);
        let notify = trigger_notify();

        loop {
            // Wait for initial trigger
            notify.notified().await;

            // Debounce: keep resetting while new notifications arrive within the window
            while tokio::time::timeout(DEBOUNCE, notify.notified())
                .await
                .is_ok()
            {}

            // Execute sync
            if let Err(err) = super::wsl_auto_sync_core(&app).await {
                tracing::warn!("WSL debounced sync failed: {}", err);
            }
        }
    }
}

/// WSL startup auto-configure: detect WSL environment and configure all CLI clients.
/// If the current listen mode is localhost, emit an event to prompt the user to switch.
#[cfg(windows)]
pub(crate) async fn wsl_auto_configure_on_startup(
    app: &tauri::AppHandle,
    db: db::Db,
    listen_mode: settings::GatewayListenMode,
    gateway_port: Option<u16>,
) -> Result<(), String> {
    // 1. Detect WSL
    let detection = blocking::run(
        "wsl_startup_detect",
        || -> crate::shared::error::AppResult<wsl::WslDetection> { Ok(wsl::detect()) },
    )
    .await
    .map_err(|e| e.to_string())?;

    if !detection.detected || detection.distros.is_empty() {
        tracing::info!("WSL startup auto-configure: no WSL environment detected, skipping");
        return Ok(());
    }

    tracing::info!(
        distros = ?detection.distros,
        "WSL startup auto-configure: detected {} WSL distro(s)",
        detection.distros.len()
    );

    // 2. If listen mode is localhost, prompt the user to switch instead of auto-switching
    if listen_mode == settings::GatewayListenMode::Localhost {
        tracing::info!(
            "WSL startup auto-configure: listen mode is localhost, prompting user to switch"
        );
        let _ = app.emit("wsl:localhost_switch_prompt", ());
        return Ok(());
    }

    // 3. Execute configuration with existing settings
    do_wsl_auto_configure(app, db, &detection.distros, listen_mode, gateway_port).await
}

#[cfg(windows)]
async fn do_wsl_auto_configure(
    app: &tauri::AppHandle,
    db: db::Db,
    distros: &[String],
    listen_mode: settings::GatewayListenMode,
    gateway_port: Option<u16>,
) -> Result<(), String> {
    let port = match gateway_port {
        Some(p) => p,
        None => {
            let report = wsl::WslConfigureReport {
                ok: false,
                message: "gateway port unknown".to_string(),
                distros: Vec::new(),
            };
            let _ = app.emit("wsl:auto_config_result", &report);
            return Err(report.message);
        }
    };

    // Read current settings to resolve host address
    let cfg = blocking::run("wsl_startup_read_cfg", {
        let app = app.clone();
        move || -> crate::shared::error::AppResult<settings::AppSettings> {
            Ok(settings::read(&app).unwrap_or_default())
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    let host = match listen_mode {
        settings::GatewayListenMode::Localhost => "127.0.0.1".to_string(),
        settings::GatewayListenMode::WslAuto | settings::GatewayListenMode::Lan => {
            wsl::resolve_wsl_host(&cfg)
        }
        settings::GatewayListenMode::Custom => {
            let parsed =
                gateway::listen::parse_custom_listen_address(&cfg.gateway_custom_listen_address)
                    .map_err(|e| format!("invalid custom listen address: {}", e))?;

            if gateway::listen::is_wildcard_host(&parsed.host) {
                wsl::resolve_wsl_host(&cfg)
            } else {
                parsed.host
            }
        }
    };

    let proxy_origin = format!("http://{}", gateway::listen::format_host_port(&host, port));

    let targets = cfg.wsl_target_cli;

    // Gather MCP and Prompt sync data
    let (mcp_data, prompt_data) = blocking::run("wsl_startup_gather_sync_data", {
        let db = db.clone();
        move || -> crate::shared::error::AppResult<(wsl::WslMcpSyncData, wsl::WslPromptSyncData)> {
            let conn = db.open_connection()?;
            let mcp = wsl::gather_mcp_sync_data(&conn)?;
            let prompts = wsl::gather_prompt_sync_data(&conn)?;
            Ok((mcp, prompts))
        }
    })
    .await
    .map_err(|e| e.to_string())?;

    let distros_owned = distros.to_vec();
    let app_for_sync = app.clone();
    let report = blocking::run(
        "wsl_startup_configure",
        move || -> crate::shared::error::AppResult<wsl::WslConfigureReport> {
            Ok(wsl::configure_clients(
                &app_for_sync,
                &distros_owned,
                &targets,
                &proxy_origin,
                Some(&mcp_data),
                Some(&prompt_data),
            ))
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    tracing::info!(
        ok = report.ok,
        message = %report.message,
        "WSL startup auto-configure completed"
    );

    let _ = app.emit("wsl:auto_config_result", &report);

    Ok(())
}
