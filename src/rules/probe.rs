// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("BashLume's probe sandbox currently supports x86_64 and aarch64 Linux");

use std::collections::{HashSet, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::ir::ProbeParser;
use super::vm::{ProbeKey, ProbeRequest};

pub const MAX_CONCURRENT_PROBES: usize = 2;
pub const MAX_QUEUED_PROBES: usize = 128;
pub const MAX_PARSED_PROBE_VALUES: usize = 4096;
pub const MAX_PROBE_VALUE_BYTES: usize = 64 * 1024;
const MAX_PROBE_ARGUMENTS: usize = 1024;
const MAX_PROBE_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_PROBE_ENVIRONMENT: usize = 256;
const MAX_PROBE_ENVIRONMENT_BYTES: usize = 256 * 1024;
const MAX_PROBE_PATH_BYTES: usize = 64 * 1024;
const PROBE_HELPER_PROTOCOL: &str = "--bashlume-probe-v1";
const MAX_PROBE_DESCENDANT_TASKS: u64 = 16;

#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub request: ProbeRequest,
    pub status: i32,
    pub values: Vec<String>,
    pub truncated: bool,
    pub error: Option<String>,
    pub completed_at: Instant,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProbeIdentity {
    key: ProbeKey,
    timeout_ms: u32,
    output_limit: u32,
    cache_ttl_ms: u32,
}

impl From<&ProbeRequest> for ProbeIdentity {
    fn from(request: &ProbeRequest) -> Self {
        Self {
            key: request.key.clone(),
            timeout_ms: request.timeout_ms,
            output_limit: request.output_limit,
            cache_ttl_ms: request.cache_ttl_ms,
        }
    }
}

#[derive(Default)]
pub struct ProbeSupervisor {
    queued: VecDeque<ProbeRequest>,
    active: Vec<ActiveProbe>,
    known: HashSet<ProbeIdentity>,
}

impl ProbeSupervisor {
    pub fn submit(&mut self, request: ProbeRequest) -> bool {
        let identity = ProbeIdentity::from(&request);
        if !request.dynamic_authorized
            || self.known.contains(&identity)
            || self.known.len() >= MAX_QUEUED_PROBES + MAX_CONCURRENT_PROBES
        {
            return false;
        }
        self.known.insert(identity);
        self.queued.push_back(request);
        self.start_ready();
        true
    }

    pub fn has_work(&self) -> bool {
        !self.queued.is_empty() || !self.active.is_empty()
    }

    pub fn poll(&mut self) -> Vec<ProbeOutcome> {
        let mut outcomes = Vec::new();
        let now = Instant::now();
        let mut index = 0;
        while index < self.active.len() {
            let result = self.active[index].poll(now);
            match result {
                ProbePoll::Pending => index += 1,
                ProbePoll::Complete {
                    status,
                    values,
                    truncated,
                    error,
                } => {
                    let active = self.active.swap_remove(index);
                    self.known.remove(&ProbeIdentity::from(&active.request));
                    outcomes.push(ProbeOutcome {
                        request: active.request.clone(),
                        status,
                        values,
                        truncated,
                        error,
                        completed_at: Instant::now(),
                    });
                }
            }
        }
        self.start_ready();
        outcomes
    }

    pub fn cancel_all(&mut self) {
        self.queued.clear();
        for active in &mut self.active {
            active.terminate();
        }
        let deadline = Instant::now() + Duration::from_millis(100);
        while !self.active.is_empty() && Instant::now() < deadline {
            for active in &mut self.active {
                active.reap();
            }
            self.active.retain(|active| !active.reaped);
            if !self.active.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // A process stuck in uninterruptible sleep must not wedge Bash. The
        // main thread keeps SIGCHLD blocked until cancellation is acknowledged;
        // after these records are dropped, Bash may reap any late exits.
        self.active.clear();
        self.known.clear();
    }

    fn start_ready(&mut self) {
        while self.active.len() < MAX_CONCURRENT_PROBES {
            let Some(request) = self.queued.pop_front() else {
                break;
            };
            match ActiveProbe::spawn(request.clone()) {
                Ok(active) => self.active.push(active),
                Err(error) => {
                    self.known.remove(&ProbeIdentity::from(&request));
                    // Preserve a completed synthetic probe so the ordinary
                    // poll path can deliver the spawn failure without adding
                    // another response channel to this small supervisor.
                    self.active
                        .push(ActiveProbe::failed(request, error.to_string()));
                }
            }
        }
    }
}

impl Drop for ProbeSupervisor {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

struct ActiveProbe {
    request: ProbeRequest,
    pid: libc::pid_t,
    stdout: RawFd,
    output: Vec<u8>,
    started: Instant,
    eof: bool,
    reaped: bool,
    status: Option<libc::c_int>,
    failure: Option<String>,
    terminated: bool,
}

impl ActiveProbe {
    fn spawn(request: ProbeRequest) -> io::Result<Self> {
        validate_request(&request)?;
        let mut pipe = [0; 2];
        // SAFETY: `pipe` points to two valid integers. Both descriptors are
        // closed on every success and failure path below.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let read_fd = pipe[0];
        let write_fd = pipe[1];
        let result = spawn_with_pipe(&request, read_fd, write_fd);
        // The parent never writes to the child stdout pipe.
        unsafe { libc::close(write_fd) };
        match result {
            Ok(pid) => {
                // SAFETY: read_fd is owned by this function and valid here.
                let current = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
                if current < 0
                    || unsafe { libc::fcntl(read_fd, libc::F_SETFL, current | libc::O_NONBLOCK) }
                        < 0
                {
                    let error = io::Error::last_os_error();
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::close(read_fd);
                    }
                    return Err(error);
                }
                Ok(Self {
                    request,
                    pid,
                    stdout: read_fd,
                    output: Vec::with_capacity(4096),
                    started: Instant::now(),
                    eof: false,
                    reaped: false,
                    status: None,
                    failure: None,
                    terminated: false,
                })
            }
            Err(error) => {
                unsafe { libc::close(read_fd) };
                Err(error)
            }
        }
    }

    fn failed(request: ProbeRequest, error: String) -> Self {
        Self {
            request,
            pid: -1,
            stdout: -1,
            output: Vec::new(),
            started: Instant::now(),
            eof: true,
            reaped: true,
            status: Some(1 << 8),
            failure: Some(error),
            terminated: false,
        }
    }

    fn poll(&mut self, now: Instant) -> ProbePoll {
        self.read_available();
        if (!self.reaped || !self.eof)
            && now.duration_since(self.started)
                >= Duration::from_millis(self.request.timeout_ms.into())
        {
            self.failure.get_or_insert_with(|| "probe timed out".into());
            self.terminate();
            if self.reaped {
                self.eof = true;
                self.close_stdout();
            }
        }
        self.reap();
        if self.terminated && self.failure.is_some() && !self.reaped {
            return ProbePoll::Complete {
                status: 1,
                values: Vec::new(),
                truncated: false,
                error: self.failure.clone(),
            };
        }
        if self.reaped {
            self.read_available();
            if !self.eof {
                // Bash owns a process-wide SIGCHLD handler and may reap a
                // probe before this supervisor observes its status. Keep
                // draining the private pipe until EOF before publishing it.
                return ProbePoll::Pending;
            }
            let status = self.status.map_or(1, |status| {
                if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                }
            });
            let (values, truncated) = if self.failure.is_none() {
                parse_output(&self.output, self.request.key.parser)
            } else {
                (Vec::new(), false)
            };
            return ProbePoll::Complete {
                status,
                values,
                truncated,
                error: self.failure.clone(),
            };
        }
        ProbePoll::Pending
    }

    fn read_available(&mut self) {
        if self.stdout < 0 || self.eof {
            return;
        }
        let mut buffer = [0_u8; 8192];
        loop {
            // SAFETY: stdout is an owned nonblocking descriptor and buffer is
            // valid for its complete length.
            let read = unsafe { libc::read(self.stdout, buffer.as_mut_ptr().cast(), buffer.len()) };
            match read.cmp(&0) {
                std::cmp::Ordering::Greater => {
                    let read = read as usize;
                    let limit = self.request.output_limit as usize;
                    if self.output.len().saturating_add(read) > limit {
                        let remaining = limit.saturating_sub(self.output.len());
                        self.output.extend_from_slice(&buffer[..remaining]);
                        self.failure
                            .get_or_insert_with(|| "probe output limit exceeded".into());
                        self.terminate();
                        break;
                    }
                    self.output.extend_from_slice(&buffer[..read]);
                }
                std::cmp::Ordering::Equal => {
                    self.eof = true;
                    self.close_stdout();
                    break;
                }
                std::cmp::Ordering::Less => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::WouldBlock {
                        self.failure
                            .get_or_insert_with(|| format!("probe output read failed: {error}"));
                        self.terminate();
                    }
                    break;
                }
            }
        }
    }

    fn reap(&mut self) {
        if self.reaped || self.pid <= 0 {
            return;
        }
        let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
        // Observe an exited leader without reaping it. Its PID/process-group ID
        // therefore cannot be reused before every still-running group member
        // has received SIGKILL.
        let observed = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if observed != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.kill_group();
                self.reaped = true;
            } else {
                self.failure
                    .get_or_insert_with(|| format!("waitid failed: {error}"));
            }
            return;
        }
        let info = unsafe { info.assume_init() };
        if unsafe { info.si_pid() } != self.pid {
            return;
        }
        self.kill_group();
        let mut status = 0;
        // SAFETY: waitid above retained this exited child with WNOWAIT.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == self.pid {
            self.reaped = true;
            self.status = Some(status);
        } else if result < 0 {
            let error = io::Error::last_os_error();
            self.reaped = true;
            if error.raw_os_error() != Some(libc::ECHILD) {
                self.failure
                    .get_or_insert_with(|| format!("waitpid failed: {error}"));
            }
        }
    }

    fn kill_group(&self) {
        if self.pid > 0 {
            // The sandbox prevents descendants from changing process groups or
            // creating sessions, so this covers the complete probe tree.
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
    }

    fn terminate(&mut self) {
        if !self.terminated && self.pid > 0 {
            self.terminated = true;
            // The child is placed in a fresh process group whose ID equals pid.
            // SAFETY: a negative pid targets only that process group.
            self.kill_group();
        }
        // Completion after a resource failure never depends on descendants
        // closing inherited descriptors; escaped pipe holders are ignored.
        self.eof = true;
        self.close_stdout();
    }

    fn close_stdout(&mut self) {
        if self.stdout >= 0 {
            unsafe { libc::close(self.stdout) };
            self.stdout = -1;
        }
    }
}

impl Drop for ActiveProbe {
    fn drop(&mut self) {
        if !self.reaped {
            self.terminate();
            self.reap();
        }
        self.close_stdout();
    }
}

enum ProbePoll {
    Pending,
    Complete {
        status: i32,
        values: Vec<String>,
        truncated: bool,
        error: Option<String>,
    },
}

fn validate_request(request: &ProbeRequest) -> io::Result<()> {
    if !request.dynamic_authorized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dynamic probe is not authorized",
        ));
    }
    let executable = request.key.executable.as_str();
    let argument_bytes = request
        .key
        .arguments
        .iter()
        .map(String::len)
        .fold(0_usize, usize::saturating_add);
    let environment_bytes = request
        .key
        .environment
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .fold(0_usize, usize::saturating_add);
    if request.key.arguments.len() > MAX_PROBE_ARGUMENTS
        || argument_bytes > MAX_PROBE_ARGUMENT_BYTES
        || request.key.environment.len() > MAX_PROBE_ENVIRONMENT
        || environment_bytes > MAX_PROBE_ENVIRONMENT_BYTES
        || request.key.working_directory.len() > MAX_PROBE_PATH_BYTES
        || request
            .key
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
        || request.key.working_directory.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe exceeds argument/environment bounds or contains NUL",
        ));
    }
    validate_probe_target(executable, &request.key.arguments)
}

fn validate_probe_target(executable: &str, arguments: &[String]) -> io::Result<()> {
    if executable.is_empty()
        || executable.len() > MAX_PROBE_VALUE_BYTES
        || executable.contains(['/', '\0'])
        || is_shell(executable)
        || executable == "bashlume-probe"
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe attempts forbidden shell or helper execution",
        ));
    }
    if matches!(
        executable,
        "env"
            | "busybox"
            | "toybox"
            | "xargs"
            | "find"
            | "nice"
            | "nohup"
            | "timeout"
            | "setsid"
            | "stdbuf"
            | "sudo"
            | "doas"
            | "chroot"
    ) && !matches!(arguments, [option] if matches!(option.as_str(), "--help" | "--version"))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe executable may forward or detach another process",
        ));
    }
    Ok(())
}

fn is_shell(value: &str) -> bool {
    matches!(value, "sh" | "bash" | "dash" | "zsh" | "fish")
}

fn spawn_with_pipe(
    request: &ProbeRequest,
    read_fd: RawFd,
    write_fd: RawFd,
) -> io::Result<libc::pid_t> {
    let spawn = probe_spawn_command(request)?;
    let mut argv = spawn
        .arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());

    let environment_strings = sanitized_environment(&request.key.environment)?;
    let mut envp = environment_strings
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    envp.push(std::ptr::null_mut());
    let cwd = CString::new(request.key.working_directory.as_str())?;

    let mut actions = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
    let mut attributes = MaybeUninit::<libc::posix_spawnattr_t>::uninit();
    // SAFETY: the opaque objects are initialized and destroyed according to
    // the POSIX spawn API. CString and pointer arrays outlive posix_spawnp.
    unsafe {
        check_spawn(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
        let mut actions = SpawnActionsGuard(actions.assume_init());
        check_spawn(libc::posix_spawn_file_actions_addopen(
            &mut actions.0,
            libc::STDIN_FILENO,
            c"/dev/null".as_ptr(),
            libc::O_RDONLY,
            0,
        ))?;
        if request.key.include_stderr {
            check_spawn(libc::posix_spawn_file_actions_adddup2(
                &mut actions.0,
                write_fd,
                libc::STDERR_FILENO,
            ))?;
        } else {
            check_spawn(libc::posix_spawn_file_actions_addopen(
                &mut actions.0,
                libc::STDERR_FILENO,
                c"/dev/null".as_ptr(),
                libc::O_WRONLY,
                0,
            ))?;
        }
        check_spawn(libc::posix_spawn_file_actions_adddup2(
            &mut actions.0,
            write_fd,
            libc::STDOUT_FILENO,
        ))?;
        check_spawn(libc::posix_spawn_file_actions_addclose(
            &mut actions.0,
            read_fd,
        ))?;
        check_spawn(libc::posix_spawn_file_actions_addclose(
            &mut actions.0,
            write_fd,
        ))?;
        check_spawn(libc::posix_spawn_file_actions_addchdir_np(
            &mut actions.0,
            cwd.as_ptr(),
        ))?;

        check_spawn(libc::posix_spawnattr_init(attributes.as_mut_ptr()))?;
        let mut attributes = SpawnAttributesGuard(attributes.assume_init());
        let mut child_mask = MaybeUninit::<libc::sigset_t>::uninit();
        if libc::sigemptyset(child_mask.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let child_mask = child_mask.assume_init();
        check_spawn(libc::posix_spawnattr_setsigmask(
            &mut attributes.0,
            &child_mask,
        ))?;
        check_spawn(libc::posix_spawnattr_setflags(
            &mut attributes.0,
            (libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_SETSIGMASK) as libc::c_short,
        ))?;
        check_spawn(libc::posix_spawnattr_setpgroup(&mut attributes.0, 0))?;

        let mut pid = 0;
        check_spawn(libc::posix_spawnp(
            &mut pid,
            spawn.executable.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        ))?;
        if !spawn.sandboxed {
            if let Err(error) = apply_probe_resource_limits(pid, request.timeout_ms) {
                libc::kill(-pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(pid, &mut status, libc::WNOHANG);
                return Err(error);
            }
        }
        Ok(pid)
    }
}

struct ProbeSpawnCommand {
    executable: CString,
    arguments: Vec<CString>,
    sandboxed: bool,
}

fn probe_spawn_command(request: &ProbeRequest) -> io::Result<ProbeSpawnCommand> {
    match probe_helper_path() {
        Ok(helper) => {
            let executable = CString::new(helper.as_os_str().as_bytes())?;
            let mut arguments = Vec::with_capacity(request.key.arguments.len() + 4);
            arguments.push(executable.clone());
            arguments.push(CString::new(PROBE_HELPER_PROTOCOL)?);
            arguments.push(CString::new(request.timeout_ms.to_string())?);
            arguments.push(CString::new(request.key.executable.as_str())?);
            for argument in &request.key.arguments {
                arguments.push(CString::new(argument.as_str())?);
            }
            Ok(ProbeSpawnCommand {
                executable,
                arguments,
                sandboxed: true,
            })
        }
        #[cfg(test)]
        Err(_) => {
            // Unit-test binaries are not accompanied by an un-hashed helper
            // on a clean `cargo test --lib` build. Production fails closed.
            let executable = CString::new(request.key.executable.as_str())?;
            let mut arguments = Vec::with_capacity(request.key.arguments.len() + 1);
            arguments.push(executable.clone());
            for argument in &request.key.arguments {
                arguments.push(CString::new(argument.as_str())?);
            }
            Ok(ProbeSpawnCommand {
                executable,
                arguments,
                sandboxed: false,
            })
        }
        #[cfg(not(test))]
        Err(error) => Err(error),
    }
}

fn probe_helper_path() -> io::Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("BASHLUME_PROBE_HELPER") {
        candidates.push(PathBuf::from(path));
    }
    let mut info = MaybeUninit::<libc::Dl_info>::zeroed();
    let address = probe_helper_path as *const () as *const libc::c_void;
    if unsafe { libc::dladdr(address, info.as_mut_ptr()) } != 0 {
        let info = unsafe { info.assume_init() };
        if !info.dli_fname.is_null() {
            let path = PathBuf::from(OsStr::from_bytes(unsafe {
                CStr::from_ptr(info.dli_fname).to_bytes()
            }));
            if let Some(parent) = path.parent() {
                candidates.push(parent.join("bashlume-probe"));
            }
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            candidates.push(parent.join("bashlume-probe"));
            if parent.file_name().is_some_and(|name| name == "deps") {
                if let Some(profile) = parent.parent() {
                    candidates.push(profile.join("bashlume-probe"));
                }
            }
        }
    }
    for candidate in candidates {
        if !candidate.is_absolute() {
            continue;
        }
        let Ok(candidate) = candidate.canonicalize() else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        let mode = metadata.permissions().mode();
        let owner = metadata.uid();
        if metadata.is_file()
            && mode & 0o111 != 0
            && mode & 0o022 == 0
            && (owner == 0 || owner == unsafe { libc::geteuid() })
        {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "trusted bashlume-probe helper was not found beside libbashlume",
    ))
}

/// Applies limits and replaces the helper with one validated probe target.
///
/// This is public only for the separately installed `bashlume-probe` binary;
/// completion packs cannot invoke it as a probe capability.
pub fn probe_helper_main(arguments: impl IntoIterator<Item = OsString>) -> io::Result<()> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(PROBE_HELPER_PROTOCOL)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid probe-helper protocol",
        ));
    }
    let timeout_ms = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=60_000).contains(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid probe timeout"))?;
    let executable = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing probe executable"))?;
    let arguments = arguments
        .map(|value| {
            value.into_string().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "probe argument is not UTF-8")
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    validate_probe_target(&executable, &arguments)?;

    if unsafe { libc::setpgid(0, 0) } != 0 && unsafe { libc::getpgrp() != libc::getpid() } {
        return Err(io::Error::last_os_error());
    }
    close_probe_inherited_descriptors()?;
    apply_probe_resource_limits(0, timeout_ms)?;
    install_probe_process_filter()?;

    let executable = CString::new(executable)?;
    let mut argument_strings = Vec::with_capacity(arguments.len() + 1);
    argument_strings.push(executable.clone());
    for argument in arguments {
        argument_strings.push(CString::new(argument)?);
    }
    let mut argv = argument_strings
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    unsafe {
        libc::execvp(executable.as_ptr(), argv.as_ptr());
    }
    Err(io::Error::last_os_error())
}

fn close_probe_inherited_descriptors() -> io::Result<()> {
    let result =
        unsafe { libc::syscall(libc::SYS_close_range, libc::STDERR_FILENO + 1, u32::MAX, 0) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EINVAL)
    ) {
        return Err(error);
    }

    // Linux before close_range(2) is uncommon but still supported. Bound the
    // fallback by the inherited descriptor ceiling; closing an absent fd is
    // harmless, and the helper needs no descriptor above stderr.
    let mut limit = MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let limit = unsafe { limit.assume_init() };
    let maximum = if limit.rlim_max == libc::RLIM_INFINITY {
        1_048_576
    } else {
        limit.rlim_max.min(1_048_576) as libc::c_int
    };
    for descriptor in (libc::STDERR_FILENO + 1)..maximum {
        unsafe {
            libc::close(descriptor);
        }
    }
    Ok(())
}

fn install_probe_process_filter() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;

    const fn statement(code: u16, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }
    const fn jump(code: u16, value: u32, yes: u8, no: u8) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: yes,
            jf: no,
            k: value,
        }
    }

    let mut filter = vec![
        statement(BPF_LD_W_ABS, 4),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH_NATIVE, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // The x32 ABI shares AUDIT_ARCH_X86_64 but ORs this bit into syscall
        // numbers. Kill it rather than permitting alternate syscall numbers.
        filter.push(jump(BPF_JMP_JSET_K, 0x4000_0000, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    }
    for syscall in [libc::SYS_setpgid, libc::SYS_setsid] {
        filter.push(jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: filter
            .len()
            .try_into()
            .map_err(|_| io::Error::other("probe seccomp filter is too large"))?,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn apply_probe_resource_limits(pid: libc::pid_t, timeout_ms: u32) -> io::Result<()> {
    let cpu_seconds = u64::from(timeout_ms).div_ceil(1000).saturating_add(1);
    let mut limits = vec![
        (libc::RLIMIT_CORE, 0_u64, 0_u64),
        (libc::RLIMIT_CPU, cpu_seconds, cpu_seconds),
        (libc::RLIMIT_FSIZE, 8 * 1024 * 1024, 8 * 1024 * 1024),
        (libc::RLIMIT_NOFILE, 64, 64),
        (libc::RLIMIT_AS, 256 * 1024 * 1024, 256 * 1024 * 1024),
    ];
    // RLIMIT_NPROC is charged against the real UID, not this process group.
    // Preserve room for the user's already-running session while limiting the
    // probe to a small amount of additional process/thread pressure.
    let tasks = current_uid_task_count()?;
    let limit = tasks.saturating_add(MAX_PROBE_DESCENDANT_TASKS);
    limits.push((libc::RLIMIT_NPROC, limit, limit));
    for (resource, soft, hard) in limits {
        let mut inherited = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let result =
            unsafe { libc::prlimit(pid, resource, std::ptr::null(), inherited.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let inherited = unsafe { inherited.assume_init() };
        let hard = (hard as libc::rlim_t).min(inherited.rlim_max);
        let soft = (soft as libc::rlim_t).min(inherited.rlim_cur).min(hard);
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        let result = unsafe { libc::prlimit(pid, resource, &limit, std::ptr::null_mut()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn current_uid_task_count() -> io::Result<u64> {
    let uid = unsafe { libc::getuid() };
    let mut tasks = 0_u64;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.uid() != uid {
            continue;
        }
        let process_tasks = match fs::read_dir(entry.path().join("task")) {
            Ok(process_tasks) => process_tasks,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for task in process_tasks {
            let task = match task {
                Ok(task) => task,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if task.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
                tasks = tasks.saturating_add(1);
            }
        }
    }
    Ok(tasks.max(1))
}

struct SpawnActionsGuard(libc::posix_spawn_file_actions_t);

impl Drop for SpawnActionsGuard {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

struct SpawnAttributesGuard(libc::posix_spawnattr_t);

impl Drop for SpawnAttributesGuard {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

fn check_spawn(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

fn sanitized_environment(overrides: &[(String, String)]) -> io::Result<Vec<CString>> {
    let mut environment = Vec::new();
    for name in ["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        if let Ok(value) = std::env::var(name) {
            if name == "PATH" && !safe_probe_path(&value) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "probe PATH must contain only bounded absolute directories",
                ));
            }
            environment.push((name.to_owned(), value));
        }
    }
    for (name, value) in overrides {
        if name.is_empty()
            || forbidden_probe_environment(name)
            || name == "PATH" && std::env::var("PATH").ok().as_deref() != Some(value)
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid probe environment name",
            ));
        }
        if let Some(existing) = environment
            .iter_mut()
            .find(|(existing, _)| existing == name)
        {
            existing.1.clone_from(value);
        } else {
            environment.push((name.clone(), value.clone()));
        }
    }
    environment
        .into_iter()
        .map(|(name, value)| CString::new(format!("{name}={value}")).map_err(Into::into))
        .collect()
}

fn safe_probe_path(value: &str) -> bool {
    let mut count = 0_usize;
    value.split(':').all(|directory| {
        count = count.saturating_add(1);
        count <= 256 && !directory.is_empty() && Path::new(directory).is_absolute()
    })
}

fn forbidden_probe_environment(name: &str) -> bool {
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("_RLD_")
        || name.starts_with("LDR_")
        || name.starts_with("GIT_CONFIG_")
        || matches!(
            name,
            "LIBPATH"
                | "SHLIB_PATH"
                | "BASH_ENV"
                | "ENV"
                | "ZDOTDIR"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "PYTHONSTARTUP"
                | "PYTHONINSPECT"
                | "PERL5LIB"
                | "PERLLIB"
                | "PERL5OPT"
                | "RUBYOPT"
                | "RUBYLIB"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "GIT_EXEC_PATH"
                | "GIT_ASKPASS"
                | "SSH_ASKPASS"
                | "LESSOPEN"
                | "LESSCLOSE"
                | "IFS"
        )
}

fn parse_output(output: &[u8], parser: ProbeParser) -> (Vec<String>, bool) {
    let text = String::from_utf8_lossy(output);
    let values: Box<dyn Iterator<Item = &str>> = match parser {
        ProbeParser::Lines => Box::new(text.lines()),
        ProbeParser::Words => Box::new(text.split_whitespace()),
        ProbeParser::Nul => Box::new(text.split('\0')),
        ProbeParser::ColonFirst => Box::new(
            text.lines()
                .map(|line| line.split(':').next().unwrap_or_default()),
        ),
        ProbeParser::TabFirst => Box::new(
            text.lines()
                .map(|line| line.split('\t').next().unwrap_or_default()),
        ),
    };
    let mut result = Vec::new();
    let mut truncated = false;
    for value in values {
        let value = value.trim_end_matches('\r');
        if value.is_empty()
            || value.len() > MAX_PROBE_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            continue;
        }
        if result.len() >= MAX_PARSED_PROBE_VALUES {
            truncated = true;
            break;
        }
        result.push(value.to_owned());
    }
    (result, truncated)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::rules::format::SourceKind;
    use crate::rules::ir::{AppendPolicy, RuleCandidateKind};

    fn request(executable: &str, arguments: &[&str]) -> ProbeRequest {
        ProbeRequest {
            key: ProbeKey {
                executable: executable.into(),
                arguments: arguments.iter().map(|value| (*value).into()).collect(),
                environment: Vec::new(),
                working_directory: Path::new("/tmp").to_string_lossy().into_owned(),
                parser: ProbeParser::Lines,
                include_stderr: false,
            },
            probe_id: "test".into(),
            candidate_kind: RuleCandidateKind::Value,
            append: AppendPolicy::Space,
            timeout_ms: 1000,
            output_limit: 64 * 1024,
            cache_ttl_ms: 1000,
            description: None,
            source: SourceKind::User,
            dynamic_authorized: true,
        }
    }

    #[test]
    fn direct_probe_uses_posix_spawn_and_parses_bounded_output() {
        let mut supervisor = ProbeSupervisor::default();
        assert!(supervisor.submit(request("printf", &["alpha\\nbeta\\nalpha\\n"])));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let outcomes = supervisor.poll();
            if let Some(outcome) = outcomes.into_iter().next() {
                assert_eq!(outcome.status, 0);
                assert_eq!(outcome.values, ["alpha", "beta", "alpha"]);
                assert!(!outcome.truncated);
                assert!(outcome.error.is_none());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn parser_marks_candidate_count_truncation_without_deduplicating() {
        let output = "same\n".repeat(MAX_PARSED_PROBE_VALUES + 1);
        let (values, truncated) = parse_output(output.as_bytes(), ProbeParser::Lines);
        assert_eq!(values.len(), MAX_PARSED_PROBE_VALUES);
        assert!(values.iter().all(|value| value == "same"));
        assert!(truncated);
    }

    #[test]
    fn unsuccessful_process_preserves_bounded_output_and_status() {
        let mut supervisor = ProbeSupervisor::default();
        let mut unsuccessful = request("ls", &["/bashlume-definitely-missing"]);
        unsuccessful.key.include_stderr = true;
        assert!(supervisor.submit(unsuccessful));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let outcomes = supervisor.poll();
            if let Some(outcome) = outcomes.into_iter().next() {
                assert_ne!(outcome.status, 0);
                assert!(!outcome.values.is_empty());
                assert!(outcome.error.is_none());
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn shell_probe_is_rejected() {
        assert!(validate_request(&request("bash", &["-c", "echo owned"])).is_err());
        assert!(validate_request(&request("env", &["bash", "-c", "echo owned"])).is_err());
        assert!(validate_request(&request("env", &["printf", "owned"])).is_err());
        assert!(validate_request(&request("env", &["--help"])).is_ok());
        assert!(validate_request(&request("nice", &["/bin/bash", "-c", "echo owned"])).is_err());
        assert!(validate_request(&request("setsid", &["printf", "owned"])).is_err());
        assert!(validate_request(&request("busybox", &["sh", "-c", "echo owned"])).is_err());
        assert!(validate_request(&request("/usr/bin/printf", &["owned"])).is_err());
    }

    #[test]
    fn probe_environment_rejects_loader_and_startup_hooks() {
        assert!(safe_probe_path("/usr/bin:/bin"));
        assert!(!safe_probe_path(".:/usr/bin"));
        assert!(!safe_probe_path(":/usr/bin"));
        for name in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "PYTHONPATH",
            "PERL5OPT",
            "RUBYOPT",
            "NODE_OPTIONS",
            "GIT_CONFIG_COUNT",
            "SSH_ASKPASS",
            "LESSOPEN",
        ] {
            assert!(sanitized_environment(&[(name.into(), "payload".into())]).is_err());
        }
    }

    #[test]
    fn oversized_probe_arguments_are_rejected_before_spawn() {
        let oversized = "x".repeat(MAX_PROBE_ARGUMENT_BYTES + 1);
        assert!(validate_request(&request("printf", &[&oversized])).is_err());
    }

    #[test]
    fn unauthorized_requests_never_enter_the_supervisor() {
        let mut supervisor = ProbeSupervisor::default();
        let mut denied = request("printf", &["owned"]);
        denied.dynamic_authorized = false;
        assert!(!supervisor.submit(denied));
        assert!(!supervisor.has_work());
    }

    #[test]
    fn supervisor_starts_at_most_two_children() {
        let mut supervisor = ProbeSupervisor::default();
        assert!(supervisor.submit(request("sleep", &["0.1"])));
        assert!(supervisor.submit(request("sleep", &["0.2"])));
        assert!(supervisor.submit(request("sleep", &["0.3"])));
        assert_eq!(supervisor.active.len(), MAX_CONCURRENT_PROBES);
        assert_eq!(supervisor.queued.len(), 1);
        supervisor.cancel_all();
    }

    #[test]
    fn timeout_completion_does_not_wait_for_inherited_pipe_eof() {
        let mut descriptors = [0; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        assert_ne!(
            unsafe { libc::fcntl(descriptors[0], libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
        let mut active = ActiveProbe {
            request: request("printf", &["unused"]),
            pid: -1,
            stdout: descriptors[0],
            output: Vec::new(),
            started: Instant::now() - Duration::from_secs(2),
            eof: false,
            reaped: false,
            status: None,
            failure: None,
            terminated: true,
        };
        assert!(matches!(
            active.poll(Instant::now()),
            ProbePoll::Complete { error: Some(_), .. }
        ));
        assert!(active.eof);
        assert_eq!(active.stdout, -1);
        unsafe { libc::close(descriptors[1]) };
    }

    #[test]
    fn exited_leader_cannot_leave_same_group_descendants_running() {
        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Only async-signal-safe operations are used after forking the
            // multi-threaded test harness.
            unsafe {
                libc::close(descriptors[0]);
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(120);
                }
                let descendant = libc::fork();
                if descendant == 0 {
                    libc::close(descriptors[1]);
                    libc::sleep(10);
                    libc::_exit(0);
                }
                if descendant < 0 {
                    libc::_exit(121);
                }
                let bytes = descendant.to_ne_bytes();
                if libc::write(descriptors[1], bytes.as_ptr().cast(), bytes.len())
                    != bytes.len() as isize
                {
                    libc::_exit(122);
                }
                libc::close(descriptors[1]);
                libc::_exit(0);
            }
        }
        assert!(pid > 0);
        unsafe { libc::close(descriptors[1]) };
        let mut descendant_bytes = [0_u8; std::mem::size_of::<libc::pid_t>()];
        let mut offset = 0;
        while offset < descendant_bytes.len() {
            let count = unsafe {
                libc::read(
                    descriptors[0],
                    descendant_bytes[offset..].as_mut_ptr().cast(),
                    descendant_bytes.len() - offset,
                )
            };
            assert!(count > 0);
            offset += count as usize;
        }
        let descendant = libc::pid_t::from_ne_bytes(descendant_bytes);
        let flags = unsafe { libc::fcntl(descriptors[0], libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(descriptors[0], libc::F_SETFL, flags | libc::O_NONBLOCK,) },
            0
        );
        let mut active = ActiveProbe {
            request: request("fixture", &[]),
            pid,
            stdout: descriptors[0],
            output: Vec::new(),
            started: Instant::now(),
            eof: false,
            reaped: false,
            status: None,
            failure: None,
            terminated: false,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let ProbePoll::Complete { error, .. } = active.poll(Instant::now()) {
                assert!(error.is_none(), "{error:?}");
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(descendant, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if unsafe { libc::kill(descendant, 0) } == 0 {
            unsafe { libc::kill(descendant, libc::SIGKILL) };
            panic!("probe descendant {descendant} survived leader completion");
        }
    }

    #[test]
    fn excessive_output_is_terminated_and_not_replayed() {
        let mut supervisor = ProbeSupervisor::default();
        let mut oversized = request("printf", &["0123456789"]);
        oversized.output_limit = 4;
        assert!(supervisor.submit(oversized));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(outcome) = supervisor.poll().into_iter().next() {
                assert!(outcome.values.is_empty());
                assert_eq!(
                    outcome.error.as_deref(),
                    Some("probe output limit exceeded")
                );
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
