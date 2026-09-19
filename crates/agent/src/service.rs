//! The Windows service: installed once, started with Windows, and small.
//!
//! A service runs in session 0, which has no desktop to capture. So the
//! service does one thing: it keeps an agent process running in whichever
//! session owns the physical console — the one someone at the machine sees —
//! and moves it when that changes (a user signs in or out, or switches). The
//! agent runs with the service's own SYSTEM token, placed in that session:
//! only SYSTEM can capture and control the sign-in screen and UAC prompts.
//! Everything else — the server connection, sessions, capture — happens in
//! that agent (`unattended`), as in portable mode.
//!
//! The service asks the agent to stop through a named event, and waits a
//! moment for it to say goodbye to its viewer and server before ending it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary, TokenSessionId,
};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateEventW, CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken,
    PROCESS_INFORMATION, ResetEvent, STARTUPINFOW, SetEvent, TerminateProcess, WaitForSingleObject,
};
use windows::core::{HSTRING, PWSTR};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::machine;

pub const SERVICE_NAME: &str = "Nearhand";
const DISPLAY_NAME: &str = "Nearhand";
const DESCRIPTION: &str = "Lets people with this computer's access password control it \
                           remotely, through the Nearhand server it was installed with.";
/// No console session at the moment, as `WTSGetActiveConsoleSessionId`
/// says during a switch.
const NO_SESSION: u32 = 0xFFFF_FFFF;
/// How long the agent gets to stop on its own before it is ended.
const STOP_GRACE: Duration = Duration::from_secs(3);
/// Restarting an agent that keeps exiting: from this, doubling, up to the max.
const RESTART_FIRST: Duration = Duration::from_secs(1);
const RESTART_MAX: Duration = Duration::from_secs(60);
/// An agent that ran this long was fine; its next exit restarts it promptly.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

// --- Installing ---------------------------------------------------------------

/// Register the service to run this executable, and start it. Replaces the
/// registration if there is one.
pub fn install(executable: &Path) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service manager (run as administrator)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments: vec![
            "--log".into(),
            machine::log_dir(&machine::dir())
                .join("service.log")
                .into_os_string(),
            "service".into(),
        ],
        dependencies: vec![],
        // LocalSystem.
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            stop_and_wait(&existing)?;
            existing
                .change_config(&info)
                .context("updating the service")?;
            existing
        }
        Err(_) => manager
            .create_service(&info, access)
            .context("creating the service")?,
    };
    service.set_description(DESCRIPTION)?;
    // If the service itself fails, Windows starts it again.
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            };
            3
        ]),
    })?;
    service
        .start::<OsString>(&[])
        .context("starting the service")?;
    Ok(())
}

/// Stop and remove the service. Its files stay unless the caller removes
/// them.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("the Nearhand service is not installed")?;
    stop_and_wait(&service)?;
    service.delete().context("removing the service")?;
    Ok(())
}

/// Restart the service, so a changed configuration takes effect.
pub fn restart() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run as administrator)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START,
        )
        .context("the Nearhand service is not installed")?;
    stop_and_wait(&service)?;
    service
        .start::<OsString>(&[])
        .context("starting the service")?;
    Ok(())
}

/// The service's state, if it is installed.
pub fn state() -> Option<ServiceState> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .ok()?;
    service.query_status().ok().map(|s| s.current_state)
}

fn stop_and_wait(service: &windows_service::service::Service) -> Result<()> {
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let _ = service.stop();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("the service did not stop within 20 seconds")
}

// --- Running, as the service ---------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

/// Hand this process to the service manager. Returns when the service stops.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("not started by the service manager: use `install` to set up the service")
}

enum Event {
    Stop,
    SessionChanged,
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = serve() {
        tracing::error!(error = %format!("{e:#}"), "the service failed");
    }
}

fn serve() -> Result<()> {
    let (events, received) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = events.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(_) => {
            let _ = events.send(Event::SessionChanged);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let report = |state, controls| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
    )?;
    tracing::info!("service running");

    let mut supervisor = Supervisor::new(std::env::current_exe()?, machine::dir())?;
    loop {
        supervisor.tend();
        match received.recv_timeout(Duration::from_secs(1)) {
            Ok(Event::Stop) => break,
            Ok(Event::SessionChanged) => tracing::info!("console session changed"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    report(ServiceState::StopPending, ServiceControlAccept::empty())?;
    supervisor.stop_agent();
    report(ServiceState::Stopped, ServiceControlAccept::empty())?;
    tracing::info!("service stopped");
    Ok(())
}

/// Keeps one agent running in the console session.
struct Supervisor {
    executable: PathBuf,
    log: PathBuf,
    agent: Option<Agent>,
    backoff: Backoff,
}

struct Agent {
    process: HANDLE,
    session: u32,
    stop: HANDLE,
    started: Instant,
}

impl Supervisor {
    fn new(executable: PathBuf, dir: PathBuf) -> Result<Self> {
        Ok(Self {
            executable,
            log: machine::log_dir(&dir).join("agent.log"),
            agent: None,
            backoff: Backoff::default(),
        })
    }

    /// Make sure an agent runs in the current console session: end one left
    /// in another session, notice one that exited, start one when due.
    fn tend(&mut self) {
        // SAFETY: no arguments; returns a session number or NO_SESSION.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if let Some(agent) = &self.agent {
            if agent.session != session {
                tracing::info!(from = agent.session, to = session, "moving the agent");
                self.stop_agent();
            } else if agent.exited() {
                let ran = agent.started.elapsed();
                tracing::warn!(?ran, "the agent exited");
                self.release();
                self.backoff.failed(ran);
            }
        }
        if self.agent.is_some() || session == NO_SESSION || !self.backoff.due() {
            return;
        }
        match self.start_agent(session) {
            Ok(agent) => {
                tracing::info!(session, "agent started");
                self.agent = Some(agent);
            }
            Err(e) => {
                tracing::error!(session, error = %format!("{e:#}"), "could not start the agent");
                self.backoff.failed(Duration::ZERO);
            }
        }
    }

    /// Start the agent in `session`, as SYSTEM.
    fn start_agent(&self, session: u32) -> Result<Agent> {
        let stop_name = format!(r"Global\NearhandAgentStop-{}-{session}", std::process::id());
        // SAFETY: handles are closed on every path, by `Agent` or below; the
        // command line buffer outlives the call that may write to it.
        unsafe {
            let stop = CreateEventW(None, true, false, &HSTRING::from(stop_name.as_str()))
                .context("creating the stop event")?;
            // The name comes back when the agent returns to a session it was
            // in; if anything still held the old event, it may be set.
            let _ = ResetEvent(stop);
            let mut own = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                &mut own,
            )
            .context("opening the service's token")?;
            let mut token = HANDLE::default();
            let duplicated = DuplicateTokenEx(
                own,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut token,
            );
            let _ = CloseHandle(own);
            duplicated.context("copying the service's token")?;
            let placed = SetTokenInformation(
                token,
                TokenSessionId,
                std::ptr::from_ref(&session).cast(),
                size_of::<u32>() as u32,
            );
            if let Err(e) = placed {
                let _ = CloseHandle(token);
                let _ = CloseHandle(stop);
                return Err(e).context("placing the token in the console session");
            }

            let command = agent_command_line(&self.executable, &self.log, &stop_name);
            let mut command: Vec<u16> = command.encode_utf16().chain([0]).collect();
            let mut desktop: Vec<u16> = r"winsta0\default".encode_utf16().chain([0]).collect();
            let startup = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_mut_ptr()),
                ..Default::default()
            };
            let mut process = PROCESS_INFORMATION::default();
            let created = CreateProcessAsUserW(
                Some(token),
                None,
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW,
                None,
                None,
                &startup,
                &mut process,
            );
            let _ = CloseHandle(token);
            if let Err(e) = created {
                let _ = CloseHandle(stop);
                return Err(e).context("starting the agent");
            }
            let _ = CloseHandle(process.hThread);
            Ok(Agent {
                process: process.hProcess,
                session,
                stop,
                started: Instant::now(),
            })
        }
    }

    /// Ask the agent to stop, and end it if it does not in time.
    fn stop_agent(&mut self) {
        let Some(agent) = &self.agent else { return };
        // SAFETY: both handles belong to `agent`, open until `release`.
        unsafe {
            let _ = SetEvent(agent.stop);
            let millis = STOP_GRACE.as_millis() as u32;
            if WaitForSingleObject(agent.process, millis) == WAIT_TIMEOUT {
                tracing::warn!("the agent did not stop in time; ending it");
                let _ = TerminateProcess(agent.process, 1);
            }
        }
        self.release();
    }

    fn release(&mut self) {
        if let Some(agent) = self.agent.take() {
            // SAFETY: owned handles, closed once.
            unsafe {
                let _ = CloseHandle(agent.process);
                let _ = CloseHandle(agent.stop);
            }
        }
    }
}

impl Agent {
    fn exited(&self) -> bool {
        // SAFETY: an owned process handle; zero timeout only polls.
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0 }
    }
}

/// The agent's command line: `"<exe>" --log "<file>" run --stop-event <name>`.
fn agent_command_line(executable: &Path, log: &Path, stop_event: &str) -> String {
    format!(
        "\"{}\" --log \"{}\" run --stop-event {stop_event}",
        executable.display(),
        log.display()
    )
}

/// When to try starting the agent again after it exits or fails to start.
#[derive(Debug)]
struct Backoff {
    wait: Duration,
    next: Instant,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            wait: RESTART_FIRST,
            next: Instant::now(),
        }
    }
}

impl Backoff {
    fn due(&self) -> bool {
        Instant::now() >= self.next
    }

    /// The agent ended after running for `ran`.
    fn failed(&mut self, ran: Duration) {
        if ran >= HEALTHY_RUN {
            self.wait = RESTART_FIRST;
        }
        self.next = Instant::now() + self.wait;
        self.wait = (self.wait * 2).min(RESTART_MAX);
    }
}

/// Wait for the service's request to stop, on a thread of its own.
pub fn stop_requested(name: &str) -> Result<tokio::sync::oneshot::Receiver<()>> {
    use windows::Win32::System::Threading::{INFINITE, OpenEventW, SYNCHRONIZATION_SYNCHRONIZE};
    // SAFETY: the handle is moved into the thread, which closes it.
    let event = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(name)) }
        .context("opening the service's stop event")?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let raw = event.0 as usize;
    std::thread::spawn(move || {
        let event = HANDLE(raw as *mut _);
        // SAFETY: an event handle this thread owns.
        unsafe {
            WaitForSingleObject(event, INFINITE);
            let _ = CloseHandle(event);
        }
        let _ = stop.send(());
    });
    Ok(stopped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_is_started_with_its_log_and_stop_event() {
        let line = agent_command_line(
            Path::new(r"C:\Program Files\Nearhand\nearhand-agent.exe"),
            Path::new(r"C:\ProgramData\Nearhand\logs\agent.log"),
            r"Global\NearhandAgentStop-4-1",
        );
        assert_eq!(
            line,
            r#""C:\Program Files\Nearhand\nearhand-agent.exe" --log "C:\ProgramData\Nearhand\logs\agent.log" run --stop-event Global\NearhandAgentStop-4-1"#
        );
    }

    #[test]
    fn restarts_back_off_until_the_agent_runs_a_while() {
        let mut backoff = Backoff::default();
        assert!(backoff.due());
        backoff.failed(Duration::ZERO);
        assert!(!backoff.due());
        assert_eq!(backoff.wait, RESTART_FIRST * 2);
        for _ in 0..10 {
            backoff.failed(Duration::ZERO);
        }
        assert_eq!(backoff.wait, RESTART_MAX);
        backoff.failed(HEALTHY_RUN);
        assert_eq!(backoff.wait, RESTART_FIRST * 2, "reset, then doubled");
    }

    /// The stop event reaches the agent's side, as it will across sessions.
    #[test]
    fn the_stop_event_is_heard() {
        let name = format!(r"Local\NearhandTestStop-{}", std::process::id());
        // SAFETY: created, signalled and closed here.
        let event = unsafe { CreateEventW(None, true, false, &HSTRING::from(name.as_str())) }
            .expect("event");
        let stopped = stop_requested(&name).expect("open");
        unsafe {
            SetEvent(event).expect("signal");
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), stopped)
                .await
                .expect("heard in time")
                .expect("sent");
        });
        unsafe {
            let _ = CloseHandle(event);
        }
    }
}
