// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{HashSet, VecDeque};
use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use super::ir::ProbeParser;
use super::vm::{ProbeKey, ProbeRequest};

pub const MAX_CONCURRENT_PROBES: usize = 2;
pub const MAX_QUEUED_PROBES: usize = 128;
pub const MAX_PARSED_PROBE_VALUES: usize = 4096;
pub const MAX_PROBE_VALUE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub request: ProbeRequest,
    pub values: Vec<String>,
    pub error: Option<String>,
    pub completed_at: Instant,
}

#[derive(Default)]
pub struct ProbeSupervisor {
    queued: VecDeque<ProbeRequest>,
    active: Vec<ActiveProbe>,
    known: HashSet<ProbeKey>,
}

impl ProbeSupervisor {
    pub fn submit(&mut self, request: ProbeRequest) -> bool {
        if !request.dynamic_authorized
            || self.known.contains(&request.key)
            || self.known.len() >= MAX_QUEUED_PROBES + MAX_CONCURRENT_PROBES
        {
            return false;
        }
        self.known.insert(request.key.clone());
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
                ProbePoll::Complete { values, error } => {
                    let active = self.active.swap_remove(index);
                    self.known.remove(&active.request.key);
                    outcomes.push(ProbeOutcome {
                        request: active.request.clone(),
                        values,
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
        while !self.active.is_empty() {
            for active in &mut self.active {
                let _ = active.poll(Instant::now());
            }
            self.active.retain(|active| !active.reaped);
        }
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
                    self.known.remove(&request.key);
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
        if self.reaped {
            self.read_available();
            if !self.eof {
                // Bash owns a process-wide SIGCHLD handler and may reap a
                // probe before this supervisor observes its status. Keep
                // draining the private pipe until EOF before publishing it.
                return ProbePoll::Pending;
            }
            let success = self.status.map_or(self.failure.is_none(), |status| {
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
            });
            if !success && self.failure.is_none() {
                self.failure = Some("probe exited unsuccessfully".into());
            }
            let values = if self.failure.is_none() {
                parse_output(&self.output, self.request.key.parser)
            } else {
                Vec::new()
            };
            return ProbePoll::Complete {
                values,
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
        let mut status = 0;
        // SAFETY: pid names the child created by this ActiveProbe. WNOHANG
        // never blocks the supervisor thread.
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

    fn terminate(&mut self) {
        if self.terminated || self.pid <= 0 {
            return;
        }
        self.terminated = true;
        // The child is placed in a fresh process group whose ID equals pid.
        // SAFETY: a negative pid targets only that process group.
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
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
        }
        if !self.reaped && self.pid > 0 {
            let mut status = 0;
            unsafe {
                libc::waitpid(self.pid, &mut status, 0);
            }
            self.reaped = true;
        }
        self.close_stdout();
    }
}

enum ProbePoll {
    Pending,
    Complete {
        values: Vec<String>,
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
    let executable = request
        .key
        .executable
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if is_shell(executable)
        || request
            .key
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
        || request.key.executable.contains('\0')
        || request.key.working_directory.contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe attempts forbidden shell execution or contains NUL",
        ));
    }
    if matches!(executable, "env" | "xargs" | "find")
        && request
            .key
            .arguments
            .iter()
            .any(|argument| is_shell(argument.rsplit('/').next().unwrap_or_default()))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe wrapper attempts to launch a shell",
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
    let executable = CString::new(request.key.executable.as_str())?;
    let mut argument_strings = Vec::with_capacity(request.key.arguments.len() + 1);
    argument_strings.push(CString::new(request.key.executable.as_str())?);
    for argument in &request.key.arguments {
        argument_strings.push(CString::new(argument.as_str())?);
    }
    let mut argv = argument_strings
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
        check_spawn(libc::posix_spawn_file_actions_addopen(
            &mut actions.0,
            libc::STDERR_FILENO,
            c"/dev/null".as_ptr(),
            libc::O_WRONLY,
            0,
        ))?;
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
        check_spawn(libc::posix_spawnattr_setflags(
            &mut attributes.0,
            libc::POSIX_SPAWN_SETPGROUP as libc::c_short,
        ))?;
        check_spawn(libc::posix_spawnattr_setpgroup(&mut attributes.0, 0))?;

        let mut pid = 0;
        check_spawn(libc::posix_spawnp(
            &mut pid,
            executable.as_ptr(),
            &actions.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        ))?;
        Ok(pid)
    }
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
            environment.push((name.to_owned(), value));
        }
    }
    for (name, value) in overrides {
        if name.is_empty()
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

fn parse_output(output: &[u8], parser: ProbeParser) -> Vec<String> {
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
    let mut seen = HashSet::new();
    for value in values {
        let value = value.trim_end_matches('\r');
        if value.is_empty() || value.len() > MAX_PROBE_VALUE_BYTES || !seen.insert(value.to_owned())
        {
            continue;
        }
        result.push(value.to_owned());
        if result.len() >= MAX_PARSED_PROBE_VALUES {
            break;
        }
    }
    result
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
                assert_eq!(outcome.values, ["alpha", "beta"]);
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
    }
}
