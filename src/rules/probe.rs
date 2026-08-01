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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::ir::ProbeParser;
use super::vm::{ProbeKey, ProbeRequest};

pub const MAX_CONCURRENT_PROBES: usize = 8;
pub const MAX_QUEUED_PROBES: usize = 128;
pub const MAX_PARSED_PROBE_VALUES: usize = 4096;
pub const MAX_PROBE_VALUE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PROBE_ARGUMENTS: usize = 1024;
pub(crate) const MAX_PROBE_ARGUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_PROBE_ENVIRONMENT: usize = 256;
pub(crate) const MAX_PROBE_ENVIRONMENT_BYTES: usize = 256 * 1024;
pub(crate) const MAX_PROBE_PATH_BYTES: usize = 64 * 1024;
const PROBE_HELPER_PROTOCOL: &str = "--bashlume-probe-v1";
const MAX_PROBE_DESCENDANT_TASKS: u64 = 16;
const PROBE_ANCHOR_READY_BYTE: u8 = 0x41;
const PROBE_START_BYTE: u8 = 0x42;
const PROBE_START_ACK_BYTE: u8 = 0x43;
const PROBE_READY_BYTE: u8 = 0x52;
const PROBE_STARTUP_TIMEOUT: Duration = Duration::from_millis(250);

static ACTIVE_PROBE_SLOTS: AtomicUsize = AtomicUsize::new(0);

fn try_acquire_global_probe_slot() -> bool {
    ACTIVE_PROBE_SLOTS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < MAX_CONCURRENT_PROBES).then_some(active + 1)
        })
        .is_ok()
}

fn release_global_probe_slot() {
    ACTIVE_PROBE_SLOTS.fetch_sub(1, Ordering::AcqRel);
}

fn try_acquire_probe_slot() -> bool {
    #[cfg(test)]
    {
        // Unit tests run many independent supervisors in parallel. The global
        // production algorithm is exercised explicitly by a serialized test.
        true
    }
    #[cfg(not(test))]
    {
        try_acquire_global_probe_slot()
    }
}

fn release_probe_slot() {
    #[cfg(not(test))]
    {
        release_global_probe_slot();
    }
}

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
        // The helper anchor owns descendant cleanup. Keep every record (and
        // its process-global concurrency slot) until the helper has exited and
        // its output pipe is closed. A caller that cannot wait detaches this
        // entire worker; it must never drop the ownership records early.
        while !self.active.is_empty() {
            let now = Instant::now();
            let mut index = 0;
            while index < self.active.len() {
                match self.active[index].poll(now) {
                    ProbePoll::Pending => index += 1,
                    ProbePoll::Complete { .. } => {
                        let active = self.active.swap_remove(index);
                        self.known.remove(&ProbeIdentity::from(&active.request));
                    }
                }
            }
            if !self.active.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.known.clear();
    }

    fn start_ready(&mut self) {
        let startup_deadline = Instant::now() + PROBE_STARTUP_TIMEOUT;
        while self.active.len() < MAX_CONCURRENT_PROBES {
            if Instant::now() >= startup_deadline {
                break;
            }
            let Some(request) = self.queued.front().cloned() else {
                break;
            };
            if !try_acquire_probe_slot() {
                break;
            }
            self.queued.pop_front();
            let handshake_deadline =
                startup_deadline - Duration::from_millis(10).min(PROBE_STARTUP_TIMEOUT);
            match ActiveProbe::spawn_before_deadline(request.clone(), handshake_deadline) {
                Ok(mut active) => {
                    active.owns_slot = true;
                    self.active.push(active);
                }
                Err(error) => {
                    release_probe_slot();
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

struct SpawnedProbe {
    pid: libc::pid_t,
    pidfd: RawFd,
    anchored: bool,
}

struct ActiveProbe {
    request: ProbeRequest,
    pid: libc::pid_t,
    pidfd: RawFd,
    anchored: bool,
    owns_slot: bool,
    stdout: RawFd,
    output: Vec<u8>,
    started: Instant,
    eof: bool,
    reaped: bool,
    status: Option<libc::c_int>,
    failure: Option<String>,
    terminated: bool,
}

fn relocate_pipe_descriptor(fd: RawFd) -> io::Result<RawFd> {
    if fd > libc::STDERR_FILENO {
        return Ok(fd);
    }
    // A shell is allowed to close a standard descriptor. Keep pipe endpoints
    // out of the stdio range so spawn actions cannot overwrite an endpoint
    // before it has been duplicated to the child's stdout/stderr.
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if relocated < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::close(fd) };
    Ok(relocated)
}

fn open_probe_pipe() -> io::Result<[RawFd; 2]> {
    let mut pipe = [0; 2];
    // SAFETY: `pipe` points to two valid integers. Both descriptors are
    // closed on every success and failure path below.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = match relocate_pipe_descriptor(pipe[0]) {
        Ok(fd) => fd,
        Err(error) => {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(error);
        }
    };
    let write_fd = match relocate_pipe_descriptor(pipe[1]) {
        Ok(fd) => fd,
        Err(error) => {
            unsafe {
                libc::close(read_fd);
                libc::close(pipe[1]);
            }
            return Err(error);
        }
    };
    Ok([read_fd, write_fd])
}

fn open_probe_start_socket() -> io::Result<[RawFd; 2]> {
    let mut sockets = [0; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sockets.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let child = match relocate_pipe_descriptor(sockets[0]) {
        Ok(fd) => fd,
        Err(error) => {
            unsafe {
                libc::close(sockets[0]);
                libc::close(sockets[1]);
            }
            return Err(error);
        }
    };
    let parent = match relocate_pipe_descriptor(sockets[1]) {
        Ok(fd) => fd,
        Err(error) => {
            unsafe {
                libc::close(child);
                libc::close(sockets[1]);
            }
            return Err(error);
        }
    };
    Ok([child, parent])
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn receive_probe_handshake(fd: RawFd, expected: u8, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe startup handshake timed out",
            ));
        }
        let timeout_ms = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let observed = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if observed == 0 {
            continue;
        }
        if observed < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        let mut byte = [0_u8; 1];
        let received = unsafe { libc::recv(fd, byte.as_mut_ptr().cast(), byte.len(), 0) };
        if received == 1 && byte[0] == expected {
            return Ok(());
        }
        return Err(if received < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "invalid probe startup handshake",
            )
        });
    }
}

fn send_probe_handshake(fd: RawFd, byte: u8) -> io::Result<()> {
    let bytes = [byte];
    let sent = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
    if sent == bytes.len() as isize {
        Ok(())
    } else if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short probe startup handshake",
        ))
    }
}

fn failed_startup_child_reaped(pid: libc::pid_t) -> bool {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            return true;
        }
        if result == 0 {
            return false;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // ECHILD means another process-wide consumer already completed the
        // direct-child ownership record; no numeric PID operation is safe.
        return true;
    }
}

fn cleanup_failed_startup_child(pid: libc::pid_t, pidfd: Option<RawFd>, terminate: bool) {
    if terminate {
        if let Some(pidfd) = pidfd {
            let _ = pidfd_send_signal(pidfd, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + Duration::from_millis(10);
    while !failed_startup_child_reaped(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    if failed_startup_child_reaped(pid) {
        if let Some(pidfd) = pidfd {
            unsafe { libc::close(pidfd) };
        }
        return;
    }

    // Transfer the caller's process-global slot to a bounded-stack cleanup
    // owner before `start_ready` releases its copy. A malicious or wedged
    // helper can consume one slot indefinitely, but can never free it early
    // and let the process accumulate unbounded orphan trees.
    #[cfg(not(test))]
    ACTIVE_PROBE_SLOTS.fetch_add(1, Ordering::AcqRel);
    let spawned = std::thread::Builder::new()
        .name("bashlume-probe-startup-cleanup".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut status = 0;
            loop {
                let result = unsafe { libc::waitpid(pid, &mut status, 0) };
                if result == pid {
                    break;
                }
                if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if let Some(pidfd) = pidfd {
                unsafe { libc::close(pidfd) };
            }
            #[cfg(not(test))]
            release_global_probe_slot();
        });
    // If thread creation fails, keep the duplicated slot and raw pidfd forever
    // rather than freeing an ownership record whose child may still be alive.
    drop(spawned);
}

fn pidfd_send_signal(pidfd: RawFd, signal: libc::c_int) -> io::Result<()> {
    if pidfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe pidfd is unavailable",
        ));
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn terminate_spawned_probe(spawned: &SpawnedProbe) {
    if spawned.anchored {
        let _ = pidfd_send_signal(spawned.pidfd, libc::SIGTERM);
    } else if spawned.pid > 0 {
        unsafe { libc::kill(-spawned.pid, libc::SIGKILL) };
    }
    if spawned.pid > 0 {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(spawned.pid, &mut status, 0) };
            if result == spawned.pid
                || result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
    }
}

impl ActiveProbe {
    #[cfg(test)]
    fn spawn(request: ProbeRequest) -> io::Result<Self> {
        let deadline =
            Instant::now() + PROBE_STARTUP_TIMEOUT.saturating_sub(Duration::from_millis(10));
        Self::spawn_before_deadline(request, deadline)
    }

    fn spawn_before_deadline(request: ProbeRequest, deadline: Instant) -> io::Result<Self> {
        validate_request(&request)?;
        let [read_fd, write_fd] = open_probe_pipe()?;
        let result = spawn_with_pipe_until(&request, read_fd, write_fd, deadline);
        // The parent never writes to the child stdout pipe.
        unsafe { libc::close(write_fd) };
        match result {
            Ok(spawned) => {
                // SAFETY: read_fd is owned by this function and valid here.
                let current = unsafe { libc::fcntl(read_fd, libc::F_GETFL) };
                if current < 0
                    || unsafe { libc::fcntl(read_fd, libc::F_SETFL, current | libc::O_NONBLOCK) }
                        < 0
                {
                    let error = io::Error::last_os_error();
                    terminate_spawned_probe(&spawned);
                    unsafe {
                        libc::close(spawned.pidfd);
                        libc::close(read_fd);
                    }
                    return Err(error);
                }
                Ok(Self {
                    request,
                    pid: spawned.pid,
                    pidfd: spawned.pidfd,
                    anchored: spawned.anchored,
                    owns_slot: false,
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
            pidfd: -1,
            anchored: true,
            owns_slot: false,
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
        }
        self.reap();
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
        if self.anchored {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.reaped = true;
                self.pid = -1;
                self.status = Some(status);
                self.close_pidfd();
            } else if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    // The direct child is a trusted subreaper anchor and exits
                    // only after killing and reaping its complete target tree.
                    // Another process-wide SIGCHLD consumer may steal this one
                    // status, but it cannot make descendant cleanup incomplete.
                    self.lose_child_ownership(
                        "probe anchor was reaped by another SIGCHLD consumer",
                    );
                } else if error.raw_os_error() != Some(libc::EINTR) {
                    self.failure
                        .get_or_insert_with(|| format!("waitpid failed: {error}"));
                }
            }
            return;
        }

        let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
        // The test-only direct-spawn fallback retains the old WNOWAIT protocol.
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
                self.lose_child_ownership("probe was reaped by another SIGCHLD consumer");
            } else if error.raw_os_error() != Some(libc::EINTR) {
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
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == self.pid {
            self.reaped = true;
            self.pid = -1;
            self.status = Some(status);
            self.close_pidfd();
        } else if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.lose_child_ownership("probe status was reaped by another SIGCHLD consumer");
            } else if error.raw_os_error() != Some(libc::EINTR) {
                self.failure
                    .get_or_insert_with(|| format!("waitpid failed: {error}"));
            }
        }
    }

    fn lose_child_ownership(&mut self, error: &str) {
        // Never signal a numeric identifier after ECHILD. Production anchors
        // have already completed descendant cleanup before this point; the
        // direct test fallback closes its output and fails conservatively.
        self.pid = -1;
        self.reaped = true;
        self.failure.get_or_insert_with(|| error.to_owned());
        self.close_pidfd();
        if !self.anchored {
            self.eof = true;
            self.close_stdout();
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
        if self.terminated || self.reaped || self.pid <= 0 {
            return;
        }
        self.terminated = true;
        if self.anchored {
            if let Err(error) = pidfd_send_signal(self.pidfd, libc::SIGTERM) {
                if error.raw_os_error() != Some(libc::ESRCH) {
                    self.failure
                        .get_or_insert_with(|| format!("probe cancellation failed: {error}"));
                }
                self.reap();
            }
        } else {
            // Detect an externally reaped direct child before attempting to
            // signal its numeric process-group ID.
            self.reap();
            if !self.reaped && self.pid > 0 {
                self.kill_group();
            }
        }
        // Raw output is already bounded. Closing it after cancellation avoids
        // waiting for pipe EOF, but completion still waits for the anchor's
        // descendant-cleanup acknowledgement (its own exit).
        self.eof = true;
        self.close_stdout();
    }

    fn close_stdout(&mut self) {
        if self.stdout >= 0 {
            unsafe { libc::close(self.stdout) };
            self.stdout = -1;
        }
    }

    fn close_pidfd(&mut self) {
        if self.pidfd >= 0 {
            unsafe { libc::close(self.pidfd) };
            self.pidfd = -1;
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
        self.close_pidfd();
        if self.owns_slot && self.reaped {
            release_probe_slot();
            self.owns_slot = false;
        }
        // If unwinding ever drops a still-owned anchor, intentionally leak its
        // global slot rather than admitting replacement work before cleanup.
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

#[cfg(test)]
fn spawn_with_pipe(
    request: &ProbeRequest,
    read_fd: RawFd,
    write_fd: RawFd,
) -> io::Result<SpawnedProbe> {
    let deadline = Instant::now() + PROBE_STARTUP_TIMEOUT.saturating_sub(Duration::from_millis(10));
    spawn_with_pipe_until(request, read_fd, write_fd, deadline)
}

fn spawn_with_pipe_until(
    request: &ProbeRequest,
    read_fd: RawFd,
    write_fd: RawFd,
    startup_deadline: Instant,
) -> io::Result<SpawnedProbe> {
    if read_fd <= libc::STDERR_FILENO || write_fd <= libc::STDERR_FILENO || read_fd == write_fd {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "probe pipe descriptors must not overlap standard descriptors",
        ));
    }
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
    let startup = if spawn.sandboxed {
        Some(open_probe_start_socket()?)
    } else {
        None
    };

    let spawned = (|| -> io::Result<libc::pid_t> {
        let mut actions = MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        let mut attributes = MaybeUninit::<libc::posix_spawnattr_t>::uninit();
        // SAFETY: the opaque objects are initialized and destroyed according
        // to the POSIX spawn API. All CString/pointer arrays outlive the call.
        unsafe {
            check_spawn(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
            let mut actions = SpawnActionsGuard(actions.assume_init());
            if let Some([child_start, parent_start]) = startup {
                check_spawn(libc::posix_spawn_file_actions_adddup2(
                    &mut actions.0,
                    child_start,
                    libc::STDIN_FILENO,
                ))?;
                check_spawn(libc::posix_spawn_file_actions_addclose(
                    &mut actions.0,
                    child_start,
                ))?;
                check_spawn(libc::posix_spawn_file_actions_addclose(
                    &mut actions.0,
                    parent_start,
                ))?;
            } else {
                check_spawn(libc::posix_spawn_file_actions_addopen(
                    &mut actions.0,
                    libc::STDIN_FILENO,
                    c"/dev/null".as_ptr(),
                    libc::O_RDONLY,
                    0,
                ))?;
            }
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
            for descriptor in [read_fd, write_fd] {
                check_spawn(libc::posix_spawn_file_actions_addclose(
                    &mut actions.0,
                    descriptor,
                ))?;
            }
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
            let mut default_signals = MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(default_signals.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut default_signals = default_signals.assume_init();
            if libc::sigaddset(&mut default_signals, libc::SIGCHLD) != 0
                || libc::sigaddset(&mut default_signals, libc::SIGTERM) != 0
            {
                return Err(io::Error::last_os_error());
            }
            check_spawn(libc::posix_spawnattr_setsigdefault(
                &mut attributes.0,
                &default_signals,
            ))?;
            let mut flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF;
            if !spawn.sandboxed {
                flags |= libc::POSIX_SPAWN_SETPGROUP;
            }
            check_spawn(libc::posix_spawnattr_setflags(
                &mut attributes.0,
                flags as libc::c_short,
            ))?;
            if !spawn.sandboxed {
                check_spawn(libc::posix_spawnattr_setpgroup(&mut attributes.0, 0))?;
            }

            let mut pid = 0;
            check_spawn(libc::posix_spawnp(
                &mut pid,
                spawn.executable.as_ptr(),
                &actions.0,
                &attributes.0,
                argv.as_ptr(),
                envp.as_ptr(),
            ))?;
            Ok(pid)
        }
    })();
    if let Some([child_start, _]) = startup {
        unsafe { libc::close(child_start) };
    }
    let pid = match spawned {
        Ok(pid) => pid,
        Err(error) => {
            if let Some([_, parent_start]) = startup {
                unsafe { libc::close(parent_start) };
            }
            return Err(error);
        }
    };
    if let Some([_, parent_start]) = startup {
        if let Err(error) =
            receive_probe_handshake(parent_start, PROBE_ANCHOR_READY_BYTE, startup_deadline)
        {
            unsafe { libc::close(parent_start) };
            cleanup_failed_startup_child(pid, None, false);
            return Err(error);
        }
    }
    let pidfd = match pidfd_open(pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            if let Some([_, parent_start]) = startup {
                unsafe { libc::close(parent_start) };
                cleanup_failed_startup_child(pid, None, false);
            } else {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
                cleanup_failed_startup_child(pid, None, false);
            }
            return Err(error);
        }
    };
    let spawned = SpawnedProbe {
        pid,
        pidfd,
        anchored: spawn.sandboxed,
    };
    if let Some([_, parent_start]) = startup {
        let handshake = send_probe_handshake(parent_start, PROBE_START_BYTE).and_then(|()| {
            receive_probe_handshake(parent_start, PROBE_START_ACK_BYTE, startup_deadline)
        });
        unsafe { libc::close(parent_start) };
        if let Err(error) = handshake {
            // The pre-open readiness byte proved that this direct child was
            // alive while pidfd_open ran, so this pidfd is already identity
            // safe even if the post-open acknowledgement fails.
            cleanup_failed_startup_child(pid, Some(pidfd), true);
            return Err(error);
        }
    }
    if !spawn.sandboxed {
        if let Err(error) = apply_probe_resource_limits(pid, request.timeout_ms) {
            terminate_spawned_probe(&spawned);
            unsafe { libc::close(pidfd) };
            return Err(error);
        }
    }
    Ok(spawned)
}

struct ProbeSpawnCommand {
    executable: CString,
    arguments: Vec<CString>,
    sandboxed: bool,
}

fn probe_spawn_command(request: &ProbeRequest) -> io::Result<ProbeSpawnCommand> {
    #[cfg(test)]
    if std::env::var_os("BASHLUME_PROBE_HELPER").is_none() {
        // Unit-test binaries can coexist with a stale helper from an earlier
        // build in target/debug. Use the direct test-only path unless a test
        // explicitly selects the freshly built helper.
        let executable = CString::new(request.key.executable.as_str())?;
        let mut arguments = Vec::with_capacity(request.key.arguments.len() + 1);
        arguments.push(executable.clone());
        for argument in &request.key.arguments {
            arguments.push(CString::new(argument.as_str())?);
        }
        return Ok(ProbeSpawnCommand {
            executable,
            arguments,
            sandboxed: false,
        });
    }
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
    run_probe_anchor(timeout_ms, executable, arguments)
}

fn run_probe_anchor(timeout_ms: u32, executable: String, arguments: Vec<String>) -> io::Result<()> {
    // Do not rely solely on the spawning shell's disposition or on the
    // posix_spawn attributes. SIG_IGN for SIGCHLD would auto-reap the target
    // and adopted descendants, destroying this anchor's ownership proof.
    let mut default_action = MaybeUninit::<libc::sigaction>::zeroed();
    if unsafe { libc::sigemptyset(&mut (*default_action.as_mut_ptr()).sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut default_action = unsafe { default_action.assume_init() };
    default_action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigaction(libc::SIGCHLD, &default_action, std::ptr::null_mut()) } != 0
        || unsafe { libc::sigaction(libc::SIGTERM, &default_action, std::ptr::null_mut()) } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let parent = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0
        || unsafe { libc::getppid() } != parent
    {
        return Err(io::Error::last_os_error());
    }
    // Become a fresh session leader before publishing readiness. The anchor
    // then has no controlling terminal through which an untrusted same-UID
    // target could synthesize job-control or input signals.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut termination_set = MaybeUninit::<libc::sigset_t>::uninit();
    if unsafe { libc::sigemptyset(termination_set.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut termination_set = unsafe { termination_set.assume_init() };
    if unsafe { libc::sigaddset(&mut termination_set, libc::SIGTERM) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_BLOCK, &termination_set, std::ptr::null_mut()) }
            != 0
    {
        return Err(io::Error::last_os_error());
    }

    // Announce that all fallible pre-handshake setup has completed. The parent
    // opens a pidfd while this trusted helper is blocked here, then requires a
    // post-open acknowledgement before it can trust that pidfd's identity.
    send_probe_handshake(libc::STDIN_FILENO, PROBE_ANCHOR_READY_BYTE)?;
    let mut start = [0_u8; 1];
    loop {
        let read = unsafe { libc::read(libc::STDIN_FILENO, start.as_mut_ptr().cast(), 1) };
        if read == 1 {
            break;
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "probe parent closed the startup handshake",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
    if start[0] != PROBE_START_BYTE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid probe startup handshake",
        ));
    }
    send_probe_handshake(libc::STDIN_FILENO, PROBE_START_ACK_BYTE)?;
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let executable = CString::new(executable)?;
    let mut argument_strings = Vec::with_capacity(arguments.len() + 1);
    argument_strings.push(executable.clone());
    for argument in arguments {
        argument_strings.push(CString::new(argument)?);
    }
    let mut ready = [0; 2];
    if unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let anchor = unsafe { libc::getpid() };
    let target = unsafe { libc::fork() };
    if target < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        return Err(error);
    }
    if target == 0 {
        unsafe { libc::close(ready[0]) };
        probe_target_child(anchor, timeout_ms, &executable, &argument_strings, ready[1]);
    }

    unsafe {
        libc::close(ready[1]);
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    // SIGTERM remains blocked until the target has either established its
    // immutable process group or exited during setup. Do not block solely on
    // the readiness pipe: parent death or cancellation must also terminate a
    // target stalled before it can report readiness.
    let cancelled = wait_for_probe_target_ready(target, ready[0], &termination_set);
    unsafe { libc::close(ready[0]) };
    supervise_probe_target(target, &termination_set, cancelled)
}

fn wait_for_probe_target_ready(
    target: libc::pid_t,
    ready_fd: RawFd,
    termination_set: &libc::sigset_t,
) -> bool {
    loop {
        let mut descriptor = libc::pollfd {
            fd: ready_fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let observed = unsafe { libc::poll(&mut descriptor, 1, 1) };
        if observed > 0 {
            let mut target_ready = [0_u8; 1];
            loop {
                let read = unsafe {
                    libc::read(
                        ready_fd,
                        target_ready.as_mut_ptr().cast(),
                        target_ready.len(),
                    )
                };
                if read >= 0 {
                    break;
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            return false;
        }
        if observed < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
        let no_wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let signal = unsafe { libc::sigtimedwait(termination_set, std::ptr::null_mut(), &no_wait) };
        if signal == libc::SIGTERM {
            // Before readiness only the numeric direct child is guaranteed to
            // exist. Kill it by owned PID; the supervision cleanup also kills
            // its group in case readiness raced with this cancellation.
            unsafe { libc::kill(target, libc::SIGKILL) };
            return true;
        }
    }
}

fn probe_target_child(
    anchor: libc::pid_t,
    timeout_ms: u32,
    executable: &CString,
    argument_strings: &[CString],
    ready_fd: RawFd,
) -> ! {
    let fail = || -> ! {
        let byte = [0_u8];
        unsafe {
            libc::write(ready_fd, byte.as_ptr().cast(), byte.len());
            libc::_exit(126);
        }
    };
    if unsafe { libc::setpgid(0, 0) } != 0 {
        fail();
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::getppid() } != anchor
    {
        fail();
    }
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if null < 0 || unsafe { libc::dup2(null, libc::STDIN_FILENO) } < 0 {
        fail();
    }
    if null != libc::STDIN_FILENO {
        unsafe { libc::close(null) };
    }
    if apply_probe_resource_limits(0, timeout_ms).is_err()
        || install_probe_process_filter().is_err()
    {
        fail();
    }
    let ready = [PROBE_READY_BYTE];
    if unsafe { libc::write(ready_fd, ready.as_ptr().cast(), ready.len()) } != ready.len() as isize
    {
        fail();
    }
    unsafe { libc::close(ready_fd) };
    if close_probe_inherited_descriptors().is_err() {
        unsafe { libc::_exit(126) };
    }
    let mut empty = MaybeUninit::<libc::sigset_t>::uninit();
    if unsafe { libc::sigemptyset(empty.as_mut_ptr()) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_SETMASK, empty.as_ptr(), std::ptr::null_mut()) }
            != 0
    {
        unsafe { libc::_exit(126) };
    }
    let mut argv = argument_strings
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    unsafe {
        libc::execvp(executable.as_ptr(), argv.as_ptr());
        libc::_exit(126);
    }
}

fn supervise_probe_target(
    target: libc::pid_t,
    termination_set: &libc::sigset_t,
    mut cancelled: bool,
) -> ! {
    let mut owns_target = true;
    while !cancelled {
        let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
        let observed = unsafe {
            libc::waitid(
                libc::P_PID,
                target as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if observed == 0 && unsafe { info.assume_init().si_pid() } == target {
            break;
        }
        if observed != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                owns_target = false;
                break;
            }
        }
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        let signal = unsafe { libc::sigtimedwait(termination_set, std::ptr::null_mut(), &timeout) };
        if signal == libc::SIGTERM {
            cancelled = true;
            break;
        }
    }

    // Never signal a numeric process-group ID after losing direct-child
    // ownership. With SIGCHLD forced to its default disposition this branch is
    // unreachable in normal operation, but it remains fail-closed against an
    // unexpected in-process reaper or kernel error.
    if !owns_target {
        unsafe { libc::_exit(1) };
    }

    // The target is still an unreaped direct child, so its process-group ID
    // cannot be reused. The seccomp policy forbids the entire tree from
    // changing group/session. Kill first, then reap the leader and every child
    // adopted through PR_SET_CHILD_SUBREAPER.
    unsafe { libc::kill(-target, libc::SIGKILL) };
    let mut target_status = 1 << 8;
    loop {
        let result = unsafe { libc::waitpid(target, &mut target_status, 0) };
        if result == target {
            break;
        }
        if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            target_status = 1 << 8;
            break;
        }
    }
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result == 0 {
            // At least one owned descendant is still alive, which keeps this
            // PGID reserved. Repeat SIGKILL to close fork-vs-signal races.
            unsafe { libc::kill(-target, libc::SIGKILL) };
            let delay = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            unsafe { libc::nanosleep(&delay, std::ptr::null_mut()) };
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    let status = if cancelled {
        128 + libc::SIGTERM
    } else if libc::WIFEXITED(target_status) {
        libc::WEXITSTATUS(target_status)
    } else if libc::WIFSIGNALED(target_status) {
        128 + libc::WTERMSIG(target_status)
    } else {
        1
    };
    unsafe { libc::_exit(status.clamp(0, 255)) }
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

    // A descriptor can remain open above a subsequently lowered RLIMIT_NOFILE,
    // so neither that limit nor an arbitrary integer ceiling is a safe
    // fallback. Enumerate the actual Linux descriptor table and fail closed
    // if procfs is unavailable.
    let directory = unsafe { libc::opendir(c"/proc/self/fd".as_ptr()) };
    if directory.is_null() {
        return Err(io::Error::last_os_error());
    }
    let directory_fd = unsafe { libc::dirfd(directory) };
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            return if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(error)
            };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        let descriptor = name.iter().try_fold(0_i32, |value, byte| {
            byte.is_ascii_digit().then(|| {
                value
                    .saturating_mul(10)
                    .saturating_add(i32::from(*byte - b'0'))
            })
        });
        if let Some(descriptor) = descriptor {
            if descriptor > libc::STDERR_FILENO && descriptor != directory_fd {
                unsafe { libc::close(descriptor) };
            }
        }
    }
}

fn install_probe_process_filter() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_ALU_AND_K: u16 = 0x54;
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
    fn append_argument_one_denials(
        filter: &mut Vec<libc::sock_filter>,
        syscall: libc::c_long,
        denied: &[u32],
    ) {
        // seccomp_data.args[1] begins at byte 24. If this is another syscall,
        // jump over the argument checks and the final syscall-number reload.
        let block_length = 2_usize.saturating_add(denied.len().saturating_mul(2));
        filter.push(jump(
            BPF_JMP_JEQ_K,
            syscall as u32,
            0,
            block_length.try_into().expect("small seccomp branch"),
        ));
        filter.push(statement(BPF_LD_W_ABS, 24));
        for &value in denied {
            filter.push(jump(BPF_JMP_JEQ_K, value, 0, 1));
            filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
        }
        filter.push(statement(BPF_LD_W_ABS, 0));
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
    // The untrusted target shares the user's credentials and can see its
    // anchor PID. Prevent it from stopping, killing, tracing, or otherwise
    // taking control of the process that proves descendant cleanup. These
    // restrictions are inherited by every target descendant.
    // Prevent asynchronous-I/O ownership from becoming an alternate signal
    // channel to the anchor. FIOSETOWN/SIOCSPGRP are the ioctl equivalents.
    append_argument_one_denials(
        &mut filter,
        libc::SYS_fcntl,
        &[
            libc::F_SETOWN as u32,
            10, // Linux F_SETSIG
            15, // Linux F_SETOWN_EX
        ],
    );
    append_argument_one_denials(
        &mut filter,
        libc::SYS_ioctl,
        &[
            0x8901, // FIOSETOWN
            0x8902, // SIOCSPGRP
            0x540e, // TIOCSCTTY
            0x5410, // TIOCSPGRP
            0x5412, // TIOCSTI
        ],
    );
    // A CLONE_PARENT child can ask the kernel to deliver its exit signal to
    // the trusted anchor, bypassing every explicit signal syscall denial.
    // Permit ordinary SIGCHLD process clones and thread clones only. clone3
    // stores flags behind a pointer that classic seccomp cannot inspect, so it
    // is denied below rather than mediated incompletely.
    filter.push(jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 9));
    filter.push(statement(BPF_LD_W_ABS, 16));
    filter.push(jump(BPF_JMP_JSET_K, libc::CLONE_PARENT as u32, 0, 1));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filter.push(jump(BPF_JMP_JSET_K, libc::CLONE_THREAD as u32, 0, 1));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    filter.push(statement(BPF_ALU_AND_K, 0xff));
    filter.push(jump(BPF_JMP_JEQ_K, libc::SIGCHLD as u32, 0, 1));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    filter.push(statement(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filter.push(statement(BPF_LD_W_ABS, 0));
    filter.push(jump(BPF_JMP_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(
        BPF_RET_K,
        SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
    ));
    for syscall in [
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
    ] {
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
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
            })
        {
            // Shell sessions commonly inherit loader/startup hooks (for
            // example SSH_ASKPASS) and exported Bash functions with names
            // that are not portable environment identifiers. Sanitization
            // means omitting them, not making every otherwise-safe probe
            // unusable for that session.
            continue;
        }
        if name == "PATH" && std::env::var("PATH").ok().as_deref() != Some(value) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "probe PATH must match the host process environment",
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
    use std::io::Read;
    use std::os::fd::FromRawFd;
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
    fn anchor_reaps_descendants_after_the_target_leader_exits() {
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let script = "import os,time\nfor attempt in range(20):\n try:\n  pid=os.fork()\n  break\n except BlockingIOError:\n  time.sleep(0.01)\nelse:\n raise RuntimeError('fork remained unavailable')\nif pid == 0:\n time.sleep(10)\n os._exit(0)\nprint(pid, flush=True)\nos._exit(0)\n";
        let mut supervisor = ProbeSupervisor::default();
        let mut probe = request("python3", &["-c", script]);
        probe.key.include_stderr = true;
        assert!(supervisor.submit(probe));
        let deadline = Instant::now() + Duration::from_secs(3);
        let descendant = loop {
            if let Some(outcome) = supervisor.poll().into_iter().next() {
                assert!(outcome.error.is_none(), "{:?}", outcome.error);
                assert_eq!(outcome.status, 0, "probe output: {:?}", outcome.values);
                break outcome.values[0].parse::<libc::pid_t>().unwrap();
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(
            unsafe { libc::kill(descendant, 0) },
            -1,
            "probe descendant {descendant} survived anchor completion"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
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
    fn inherited_ignored_sigchld_is_normalized_before_probe_spawn() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rules::probe::tests::ignored_sigchld_probe_child",
                "--ignored",
                "--nocapture",
            ])
            .env("BASHLUME_IGNORED_SIGCHLD_CHILD", "1")
            .env_remove("BASHLUME_PROBE_HELPER")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "executed in an isolated subprocess by the SIGCHLD regression"]
    fn ignored_sigchld_probe_child() {
        if std::env::var_os("BASHLUME_IGNORED_SIGCHLD_CHILD").is_none() {
            return;
        }
        let ignored = libc::sigaction {
            sa_sigaction: libc::SIG_IGN,
            sa_mask: unsafe { std::mem::zeroed() },
            sa_flags: 0,
            sa_restorer: None,
        };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, &ignored, std::ptr::null_mut()) },
            0
        );
        let executable = std::env::current_exe().unwrap();
        let mut probe = request(
            executable.to_str().unwrap(),
            &[
                "--exact",
                "rules::probe::tests::default_sigchld_probe_grandchild",
                "--ignored",
                "--nocapture",
            ],
        );
        probe.key.environment = vec![("BASHLUME_SIGCHLD_GRANDCHILD".into(), "1".into())];
        let [read_fd, write_fd] = open_probe_pipe().unwrap();
        let spawned = spawn_with_pipe(&probe, read_fd, write_fd).unwrap();
        unsafe { libc::close(write_fd) };
        let mut output = String::new();
        unsafe { fs::File::from_raw_fd(read_fd) }
            .read_to_string(&mut output)
            .unwrap();
        unsafe { libc::close(spawned.pidfd) };
        // This isolated parent intentionally auto-reaps its direct probe. The
        // captured output proves the spawned process itself received SIG_DFL
        // and successfully owned/reaped its descendant.
        assert!(output.contains("SIGCHLD_NORMALIZED"), "{output}");
    }

    #[test]
    #[ignore = "executed in an isolated subprocess by the SIGCHLD regression"]
    fn default_sigchld_probe_grandchild() {
        if std::env::var_os("BASHLUME_SIGCHLD_GRANDCHILD").is_none() {
            return;
        }
        // Keep this direct child alive long enough for the isolated ignored-
        // SIGCHLD parent to bind its pidfd before that parent auto-reaps it.
        std::thread::sleep(Duration::from_millis(50));
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) },
            0
        );
        assert_eq!(unsafe { action.assume_init() }.sa_sigaction, libc::SIG_DFL);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        println!("SIGCHLD_NORMALIZED");
    }

    #[test]
    fn probe_environment_strips_loader_and_startup_hooks() {
        assert!(safe_probe_path("/usr/bin:/bin"));
        assert!(!safe_probe_path(".:/usr/bin"));
        assert!(!safe_probe_path(":/usr/bin"));
        for name in [
            "BASH_FUNC_exported%%",
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
            let environment = sanitized_environment(&[(name.into(), "payload".into())]).unwrap();
            assert!(
                environment
                    .iter()
                    .all(|entry| { !entry.to_bytes().starts_with(format!("{name}=").as_bytes()) })
            );
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
    fn probe_pipe_descriptors_never_overlap_standard_descriptors() {
        let [read_fd, write_fd] = open_probe_pipe().unwrap();
        assert!(read_fd > libc::STDERR_FILENO);
        assert!(write_fd > libc::STDERR_FILENO);
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        assert!(spawn_with_pipe(&request("printf", &["unused"]), 1, 3).is_err());
        assert!(spawn_with_pipe(&request("printf", &["unused"]), 3, 2).is_err());
    }

    #[test]
    fn externally_reaped_probe_relinquishes_the_numeric_process_group() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let mut active = ActiveProbe {
            request: request("printf", &["unused"]),
            pid,
            pidfd: -1,
            anchored: false,
            owns_slot: false,
            stdout: -1,
            output: Vec::new(),
            started: Instant::now(),
            eof: true,
            reaped: false,
            status: None,
            failure: None,
            terminated: false,
        };

        active.reap();

        assert!(active.reaped);
        assert_eq!(active.pid, -1);
        assert!(
            active
                .failure
                .as_deref()
                .is_some_and(|error| error.contains("reaped"))
        );
    }

    #[test]
    fn externally_reaped_anchor_has_already_completed_tree_cleanup() {
        let mut active = ActiveProbe::spawn(request("printf", &["anchored\\n"])).unwrap();
        if !active.anchored {
            // A clean unit-test build may not have built the separately
            // installed helper binary; production never uses this fallback.
            active.terminate();
            while !active.reaped {
                active.reap();
                std::thread::sleep(Duration::from_millis(1));
            }
            return;
        }
        let helper = active.pid;
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(helper, &mut status, 0) };
            if result == helper {
                break;
            }
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let ProbePoll::Complete { error, .. } = active.poll(Instant::now()) {
                assert!(
                    error
                        .as_deref()
                        .is_some_and(|error| error.contains("anchor") && error.contains("reaped"))
                );
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(active.pid, -1);
        assert!(active.reaped);
    }

    #[test]
    fn failed_startup_cleanup_returns_before_a_wedged_child_exits() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let delay = libc::timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            };
            unsafe {
                libc::nanosleep(&delay, std::ptr::null_mut());
                libc::_exit(0);
            }
        }
        let started = Instant::now();
        cleanup_failed_startup_child(pid, None, false);
        assert!(started.elapsed() < Duration::from_millis(75));
    }

    #[test]
    fn process_global_slots_remain_reserved_for_a_detached_cleanup_owner() {
        static SLOT_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = SLOT_TEST.lock().unwrap();
        ACTIVE_PROBE_SLOTS.store(0, Ordering::Release);
        for _ in 0..MAX_CONCURRENT_PROBES {
            assert!(try_acquire_global_probe_slot());
        }
        // Dropping a supervisor thread does not release leases owned by its
        // detached process-tree cleanup. New supervisors remain backpressured.
        assert!(!try_acquire_global_probe_slot());
        release_global_probe_slot();
        assert!(try_acquire_global_probe_slot());
        for _ in 0..MAX_CONCURRENT_PROBES {
            release_global_probe_slot();
        }
        assert_eq!(ACTIVE_PROBE_SLOTS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn supervisor_starts_at_most_the_configured_number_of_children() {
        let mut supervisor = ProbeSupervisor::default();
        for index in 0..=MAX_CONCURRENT_PROBES {
            let mut probe = request("sleep", &[]);
            probe.key.arguments = vec![format!("0.{:03}", index + 1)];
            assert!(supervisor.submit(probe));
        }
        assert_eq!(supervisor.active.len(), MAX_CONCURRENT_PROBES);
        assert_eq!(supervisor.queued.len(), 1);
        supervisor.cancel_all();
    }

    #[test]
    fn cancellation_interrupts_the_target_readiness_wait() {
        let mut announced = [0; 2];
        let mut ready = [0; 2];
        assert_eq!(unsafe { libc::pipe(announced.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
        let anchor = unsafe { libc::fork() };
        assert!(anchor >= 0);
        if anchor == 0 {
            unsafe {
                libc::close(announced[0]);
                let mut set = MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigemptyset(set.as_mut_ptr()) != 0 {
                    libc::_exit(120);
                }
                let mut set = set.assume_init();
                if libc::sigaddset(&mut set, libc::SIGTERM) != 0
                    || libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0
                {
                    libc::_exit(121);
                }
                let target = libc::fork();
                if target < 0 {
                    libc::_exit(122);
                }
                if target == 0 {
                    libc::close(ready[0]);
                    if libc::setpgid(0, 0) != 0 {
                        libc::_exit(123);
                    }
                    let byte = [1_u8];
                    libc::write(announced[1], byte.as_ptr().cast(), byte.len());
                    libc::close(announced[1]);
                    loop {
                        libc::pause();
                    }
                }
                libc::close(announced[1]);
                libc::close(ready[1]);
                let cancelled = wait_for_probe_target_ready(target, ready[0], &set);
                libc::close(ready[0]);
                if !cancelled {
                    libc::kill(target, libc::SIGKILL);
                    libc::_exit(124);
                }
                supervise_probe_target(target, &set, true);
            }
        }
        unsafe {
            libc::close(announced[1]);
            libc::close(ready[0]);
            libc::close(ready[1]);
        }
        let mut byte = [0_u8; 1];
        assert_eq!(
            unsafe { libc::read(announced[0], byte.as_mut_ptr().cast(), byte.len()) },
            1
        );
        unsafe { libc::close(announced[0]) };
        let anchor_pidfd = pidfd_open(anchor).unwrap();
        pidfd_send_signal(anchor_pidfd, libc::SIGTERM).unwrap();
        unsafe { libc::close(anchor_pidfd) };

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(anchor, &mut status, libc::WNOHANG) };
            if result == anchor {
                break;
            }
            assert_eq!(result, 0);
            assert!(
                Instant::now() < deadline,
                "anchor ignored cancellation while its target withheld readiness"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 128 + libc::SIGTERM);
    }

    #[test]
    fn timeout_does_not_complete_before_anchor_cleanup() {
        let mut descriptors = [0; 2];
        let mut ready = [0; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
                libc::close(ready[0]);
                let mut set = MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigemptyset(set.as_mut_ptr()) != 0 {
                    libc::_exit(120);
                }
                let mut set = set.assume_init();
                if libc::sigaddset(&mut set, libc::SIGTERM) != 0
                    || libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0
                {
                    libc::_exit(121);
                }
                let byte = [1_u8];
                libc::write(ready[1], byte.as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        unsafe {
            libc::close(ready[1]);
            libc::close(descriptors[1]);
        }
        let mut byte = [0_u8; 1];
        assert_eq!(
            unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 1) },
            1
        );
        unsafe { libc::close(ready[0]) };
        let pidfd = pidfd_open(pid).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(descriptors[0], libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
        let mut active = ActiveProbe {
            request: request("printf", &["unused"]),
            pid,
            pidfd,
            anchored: true,
            owns_slot: false,
            stdout: descriptors[0],
            output: Vec::new(),
            started: Instant::now() - Duration::from_secs(2),
            eof: false,
            reaped: false,
            status: None,
            failure: None,
            terminated: false,
        };
        assert!(matches!(active.poll(Instant::now()), ProbePoll::Pending));
        assert!(active.eof);
        assert_eq!(active.stdout, -1);

        pidfd_send_signal(active.pidfd, libc::SIGKILL).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if matches!(
                active.poll(Instant::now()),
                ProbePoll::Complete { error: Some(_), .. }
            ) {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
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
            pidfd: -1,
            anchored: false,
            owns_slot: false,
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
