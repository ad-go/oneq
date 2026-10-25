//! Windows service "oneq": runs the node in the background from boot, as LocalSystem (needed to create the Wintun
//! adapter), restarted by the service manager if the process dies.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::Notify;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::svc::{self, ServiceConfig};
use crate::Status;

pub const NAME: &str = "oneq";
const TYPE: ServiceType = ServiceType::OWN_PROCESS;

static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Entry of `oneqclient service run`: hands the process to the service control manager.
pub fn dispatch(config: &Path) -> Result<()> {
    let _ = CONFIG_PATH.set(config.to_path_buf());
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| anyhow!("not started by the service manager: {e}"))
}

fn report(h: &service_control_handler::ServiceStatusHandle, state: ServiceState, code: u32) {
    let accepted = if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() };
    let _ = h.set_service_status(ServiceStatus {
        service_type: TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: if state == ServiceState::StopPending { Duration::from_secs(10) } else { Duration::default() },
        process_id: None,
    });
}

fn service_main(_args: Vec<OsString>) {
    let stop = Arc::new(Notify::new());
    let s = stop.clone();
    let handler = match service_control_handler::register(NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(h) => h,
        Err(_) => return,
    };
    report(&handler, ServiceState::StartPending, 0);
    svc::init_file_logging(&svc::service_dir().join("client.log"));
    let code = match run(stop, &handler) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("service failed: {e:#}");
            1
        }
    };
    report(&handler, ServiceState::Stopped, code);
}

fn run(stop: Arc<Notify>, handler: &service_control_handler::ServiceStatusHandle) -> Result<()> {
    let path = CONFIG_PATH.get().cloned().unwrap_or_else(svc::default_config_path);
    let mut cfg = ServiceConfig::load(&path)?;
    if cfg.wintun.is_none() {
        cfg.wintun = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("wintun.dll").to_string_lossy().into_owned()));
    }
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    report(handler, ServiceState::Running, 0);
    tracing::info!("oneq service started ({})", path.display());
    let status = Arc::new(Status::new());
    rt.block_on(svc::supervise(cfg, status, stop));
    report(handler, ServiceState::StopPending, 0);
    tracing::info!("oneq service stopped");
    rt.shutdown_timeout(Duration::from_secs(3));
    Ok(())
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(|e| anyhow!("service manager: {e} (administrator rights are required)"))
}

pub fn install(exe: &Path, config: &Path, autostart: bool) -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "oneq post-quantum mesh node".into(),
        service_type: TYPE,
        start_type: if autostart { ServiceStartType::AutoStart } else { ServiceStartType::OnDemand },
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec!["service".into(), "run".into(), "--config".into(), config.as_os_str().to_owned()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let s = m
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| anyhow!("create service: {e} (already installed? run `service uninstall` first)"))?;
    s.set_description("Post-quantum layer-2 mesh VPN node (oneq). Keeps the node connected to its community.")
        .map_err(|e| anyhow!("{e}"))?;
    s.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(10) }; 3]),
    })
    .map_err(|e| anyhow!("failure actions: {e}"))?;
    Ok(())
}

fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    m.open_service(NAME, access).map_err(|e| anyhow!("service '{NAME}' not found or not accessible: {e}"))
}

pub fn state() -> Result<ServiceState> {
    Ok(open(ServiceAccess::QUERY_STATUS)?.query_status().map_err(|e| anyhow!("{e}"))?.current_state)
}

pub fn start() -> Result<()> {
    open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?.start::<&str>(&[]).map_err(|e| anyhow!("start: {e}"))
}

pub fn stop() -> Result<()> {
    let s = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state != ServiceState::Stopped {
        let _ = s.stop();
    }
    for _ in 0..40 {
        if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(anyhow!("the service did not stop within 20 s"))
}

pub fn uninstall() -> Result<()> {
    let s = open(ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state != ServiceState::Stopped {
        let _ = s.stop();
        for _ in 0..40 {
            if s.query_status().map_err(|e| anyhow!("{e}"))?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    s.delete().map_err(|e| anyhow!("delete: {e}"))
}
