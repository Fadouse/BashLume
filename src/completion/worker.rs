use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{
    self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::matcher::match_score;
use crate::rules::loader::{LoadedProgram, PackSummary, RuleStore};
use crate::rules::probe::ProbeSupervisor;
use crate::rules::vm::{FilesystemRequest, ProbeKey, ProbeRequest, ProbeResult};

const MAX_PATH_DIRECTORIES: usize = 256;
const MAX_FILESYSTEM_CACHE_ENTRIES: usize = 128;
const FILESYSTEM_CACHE_TTL: Duration = Duration::from_secs(2);
const MAX_DIRECTORY_CACHE_ENTRIES: usize = 4096;
const MAX_RULE_CACHE_ENTRIES: usize = 4096;
const MAX_PROBE_CACHE_ENTRIES: usize = 1024;
const MAX_WORKER_REQUESTS: usize = 512;
const MAX_PENDING_SCANS: usize = 512;
const MAX_PENDING_RULE_REQUESTS: usize = 512;
const MAX_PROBE_WORKER_REQUESTS: usize = 8;

static MAIN_PROBE_MASK_ACTIVE: AtomicBool = AtomicBool::new(false);
static MAIN_PROBE_SIGCHLD_WAS_BLOCKED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    Executable,
}

#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ScanKey {
    pub directory: PathBuf,
    pub prefix: String,
    pub executable_only: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FilesystemKey {
    request: FilesystemRequest,
    working_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProbeCacheKey {
    key: ProbeKey,
    timeout_ms: u32,
    output_limit: u32,
    cache_ttl_ms: u32,
}

impl From<&ProbeRequest> for ProbeCacheKey {
    fn from(request: &ProbeRequest) -> Self {
        Self {
            key: request.key.clone(),
            timeout_ms: request.timeout_ms,
            output_limit: request.output_limit,
            cache_ttl_ms: request.cache_ttl_ms,
        }
    }
}

#[derive(Debug)]
enum Request {
    Scan {
        key: ScanKey,
        max_candidates: usize,
        generation: u64,
    },
    LoadSnapshots {
        home: Option<PathBuf>,
    },
    ResolveFilesystem {
        key: FilesystemKey,
        generation: u64,
    },
    DiscoverRules {
        paths: Vec<PathBuf>,
        trusted_key_paths: Vec<PathBuf>,
        generation: u64,
    },
    LoadRules {
        command: String,
        generation: u64,
    },
    Stop,
}

#[derive(Debug)]
enum Response {
    Scan {
        key: ScanKey,
        entries: Vec<DirectoryEntry>,
        truncated: bool,
        generation: u64,
        completed_at: Instant,
    },
    Filesystem {
        key: FilesystemKey,
        values: Vec<String>,
        generation: u64,
        completed_at: Instant,
    },
    Snapshots {
        users: Vec<String>,
        groups: Vec<String>,
        passwd_records: Vec<String>,
        group_records: Vec<String>,
        hosts: Vec<String>,
        process_ids: Vec<String>,
        process_names: Vec<String>,
        network_interfaces: Vec<String>,
    },
    RuleCatalog {
        summaries: Vec<PackSummary>,
        generation: u64,
    },
    Rules {
        command: String,
        programs: Vec<LoadedProgram>,
        errors: Vec<String>,
        generation: u64,
    },
}

pub struct WorkerClient {
    requests: Option<SyncSender<Request>>,
    responses: Receiver<Response>,
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    filesystem_generation: Arc<AtomicU64>,
}

impl WorkerClient {
    pub fn start() -> std::io::Result<Self> {
        let (request_tx, request_rx) = mpsc::sync_channel(MAX_WORKER_REQUESTS);
        let (response_tx, response_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let filesystem_generation = Arc::new(AtomicU64::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_filesystem_generation = Arc::clone(&filesystem_generation);
        let handle = thread::Builder::new()
            .name("bashlume-cache".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                worker_loop(
                    request_rx,
                    response_tx,
                    worker_stop,
                    worker_filesystem_generation,
                )
            })?;
        Ok(Self {
            requests: Some(request_tx),
            responses: response_rx,
            handle: Some(handle),
            stop,
            filesystem_generation,
        })
    }

    fn send(&self, request: Request) -> bool {
        let Some(requests) = self.requests.as_ref() else {
            return false;
        };
        requests.try_send(request).is_ok()
    }

    fn cancel_filesystem(&self) -> u64 {
        self.filesystem_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1)
    }

    fn try_receive(&self) -> Result<Response, TryRecvError> {
        self.responses.try_recv()
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.stop.store(true, Ordering::Release);
            if let Some(requests) = self.requests.take() {
                match requests.try_send(Request::Stop) {
                    Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                    Err(TrySendError::Full(_)) => {
                        // Dropping the final sender wakes a receiver after its
                        // bounded backlog; the atomic stop flag makes it exit
                        // before executing another queued request.
                    }
                }
            }
            let _ = handle.join();
        }
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
enum ProbeWorkerRequest {
    Run {
        request: Box<ProbeRequest>,
        generation: u64,
    },
    Wake,
    Stop,
}

#[derive(Debug)]
enum ProbeResponse {
    Outcome {
        request: Box<ProbeRequest>,
        generation: u64,
        status: i32,
        values: Vec<String>,
        truncated: bool,
        error: Option<String>,
        completed_at: Instant,
    },
    Cancelled {
        generation: u64,
    },
}

struct ProbeClient {
    requests: Option<SyncSender<ProbeWorkerRequest>>,
    responses: Receiver<ProbeResponse>,
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
}

impl ProbeClient {
    fn start() -> std::io::Result<Self> {
        let (request_tx, request_rx) = mpsc::sync_channel(MAX_PROBE_WORKER_REQUESTS);
        let (response_tx, response_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let generation = Arc::new(AtomicU64::new(0));
        let worker_stop = Arc::clone(&stop);
        let worker_generation = Arc::clone(&generation);
        let handle = thread::Builder::new()
            .name("bashlume-probes".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                probe_worker_loop(request_rx, response_tx, worker_stop, worker_generation)
            })?;
        Ok(Self {
            requests: Some(request_tx),
            responses: response_rx,
            handle: Some(handle),
            stop,
            generation,
        })
    }

    fn send_probe(&self, request: ProbeRequest, generation: u64) -> bool {
        self.requests.as_ref().is_some_and(|requests| {
            requests
                .try_send(ProbeWorkerRequest::Run {
                    request: Box::new(request),
                    generation,
                })
                .is_ok()
        })
    }

    fn cancel(&self) -> u64 {
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        if let Some(requests) = &self.requests {
            let _ = requests.try_send(ProbeWorkerRequest::Wake);
        }
        generation
    }

    fn try_receive(&self) -> Result<ProbeResponse, TryRecvError> {
        self.responses.try_recv()
    }

    fn stop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.stop.store(true, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(requests) = self.requests.take() {
            match requests.try_send(ProbeWorkerRequest::Stop) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                Err(TrySendError::Full(_)) => {}
            }
        }
        let _ = handle.join();
    }
}

impl Drop for ProbeClient {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct CacheEntry {
    entries: Vec<DirectoryEntry>,
    truncated: bool,
    approximate_bytes: usize,
    last_used: u64,
    refreshed_at: Instant,
}

struct FilesystemCacheEntry {
    values: Vec<String>,
    approximate_bytes: usize,
    last_used: u64,
    refreshed_at: Instant,
}

struct RuleCacheEntry {
    programs: Vec<LoadedProgram>,
    approximate_bytes: usize,
    last_used: u64,
}

struct ProbeCacheEntry {
    values: Vec<String>,
    status: i32,
    truncated: bool,
    failed: bool,
    refreshed_at: Instant,
    ttl: Duration,
    approximate_bytes: usize,
    last_used: u64,
}

fn scan_key_bytes(key: &ScanKey) -> usize {
    std::mem::size_of::<ScanKey>()
        .saturating_add(key.directory.as_os_str().as_bytes().len())
        .saturating_add(key.prefix.capacity())
}

fn filesystem_key_bytes(key: &FilesystemKey) -> usize {
    std::mem::size_of::<FilesystemKey>()
        .saturating_add(key.working_directory.as_os_str().as_bytes().len())
        .saturating_add(key.request.request_id.capacity())
        .saturating_add(key.request.path.capacity())
        .saturating_add(key.request.operator.as_ref().map_or(0, String::capacity))
}

fn probe_key_bytes(cache_key: &ProbeCacheKey) -> usize {
    let key = &cache_key.key;
    std::mem::size_of::<ProbeCacheKey>()
        .saturating_add(key.executable.capacity())
        .saturating_add(key.working_directory.capacity())
        .saturating_add(
            key.arguments
                .iter()
                .map(|argument| std::mem::size_of::<String>().saturating_add(argument.capacity()))
                .sum::<usize>(),
        )
        .saturating_add(
            key.environment
                .iter()
                .map(|(name, value)| {
                    std::mem::size_of::<(String, String)>()
                        .saturating_add(name.capacity())
                        .saturating_add(value.capacity())
                })
                .sum::<usize>(),
        )
}

struct SignalMaskGuard {
    previous: libc::sigset_t,
    registered_main_probe_mask: bool,
}

impl SignalMaskGuard {
    fn block_sigchld() -> std::io::Result<Self> {
        Self::block_sigchld_inner(false)
    }

    fn block_main_probe_sigchld() -> std::io::Result<Self> {
        Self::block_sigchld_inner(true)
    }

    fn block_sigchld_inner(registered_main_probe_mask: bool) -> std::io::Result<Self> {
        let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        unsafe {
            if libc::sigemptyset(blocked.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut blocked = blocked.assume_init();
            if libc::sigaddset(&mut blocked, libc::SIGCHLD) != 0
                || libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr()) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let previous = previous.assume_init();
            if registered_main_probe_mask {
                MAIN_PROBE_SIGCHLD_WAS_BLOCKED.store(
                    libc::sigismember(&previous, libc::SIGCHLD) == 1,
                    Ordering::Relaxed,
                );
                MAIN_PROBE_MASK_ACTIVE.store(true, Ordering::Release);
            }
            Ok(Self {
                previous,
                registered_main_probe_mask,
            })
        }
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
        if self.registered_main_probe_mask {
            MAIN_PROBE_MASK_ACTIVE.store(false, Ordering::Release);
        }
    }
}

/// Restore the main thread's pre-probe SIGCHLD state in an at-fork child.
/// Only async-signal-safe libc operations and atomics are used here.
pub(crate) unsafe fn restore_probe_signal_mask_after_fork() {
    if !MAIN_PROBE_MASK_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let mut signal_set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    unsafe {
        if libc::sigemptyset(signal_set.as_mut_ptr()) != 0 {
            return;
        }
        let mut signal_set = signal_set.assume_init();
        if libc::sigaddset(&mut signal_set, libc::SIGCHLD) != 0 {
            return;
        }
        let operation = if MAIN_PROBE_SIGCHLD_WAS_BLOCKED.load(Ordering::Relaxed) {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        let _ = libc::sigprocmask(operation, &signal_set, std::ptr::null_mut());
    }
    MAIN_PROBE_MASK_ACTIVE.store(false, Ordering::Release);
}

pub struct CompletionCache {
    worker: Option<WorkerClient>,
    probe_worker: Option<ProbeClient>,
    entries: HashMap<ScanKey, CacheEntry>,
    pending: HashSet<ScanKey>,
    scan_deferred: HashSet<ScanKey>,
    directory_generations: HashMap<PathBuf, u64>,
    path_directories: Vec<PathBuf>,
    users: Vec<String>,
    groups: Vec<String>,
    passwd_records: Vec<String>,
    group_records: Vec<String>,
    hosts: Vec<String>,
    process_ids: Vec<String>,
    process_names: Vec<String>,
    network_interfaces: Vec<String>,
    snapshot_bytes: usize,
    filesystem_entries: HashMap<FilesystemKey, FilesystemCacheEntry>,
    filesystem_pending: HashSet<FilesystemKey>,
    filesystem_pins: HashSet<FilesystemKey>,
    filesystem_limit_exceeded: bool,
    filesystem_generation: u64,
    byte_limit: usize,
    used_bytes: usize,
    clock: u64,
    max_candidates: usize,
    snapshots_requested: bool,
    rule_generation: u64,
    rule_catalog_ready: bool,
    rule_summaries: Vec<PackSummary>,
    rule_entries: HashMap<String, RuleCacheEntry>,
    rule_pending: HashSet<String>,
    rule_deferred: HashSet<String>,
    rule_catalog_deferred: bool,
    rule_errors: Vec<String>,
    rule_configuration: Option<(Vec<PathBuf>, Vec<PathBuf>)>,
    probe_entries: HashMap<ProbeCacheKey, ProbeCacheEntry>,
    probe_pending: HashSet<ProbeCacheKey>,
    probe_pins: HashSet<ProbeCacheKey>,
    probe_fresh: HashSet<ProbeCacheKey>,
    probe_errors: Vec<String>,
    probe_generation: u64,
    probe_cancel_pending: Option<u64>,
    probe_signal_mask: Option<SignalMaskGuard>,
}

impl CompletionCache {
    pub fn new(byte_limit: usize, max_candidates: usize) -> Self {
        Self {
            worker: WorkerClient::start().ok(),
            probe_worker: ProbeClient::start().ok(),
            entries: HashMap::new(),
            pending: HashSet::new(),
            scan_deferred: HashSet::new(),
            directory_generations: HashMap::new(),
            path_directories: Vec::new(),
            users: Vec::new(),
            groups: Vec::new(),
            passwd_records: Vec::new(),
            group_records: Vec::new(),
            hosts: Vec::new(),
            process_ids: Vec::new(),
            process_names: Vec::new(),
            network_interfaces: Vec::new(),
            snapshot_bytes: 0,
            filesystem_entries: HashMap::new(),
            filesystem_pending: HashSet::new(),
            filesystem_pins: HashSet::new(),
            filesystem_limit_exceeded: false,
            filesystem_generation: 0,
            byte_limit,
            used_bytes: 0,
            clock: 0,
            max_candidates,
            snapshots_requested: false,
            rule_generation: 0,
            rule_catalog_ready: true,
            rule_summaries: Vec::new(),
            rule_entries: HashMap::new(),
            rule_pending: HashSet::new(),
            rule_deferred: HashSet::new(),
            rule_catalog_deferred: false,
            rule_errors: Vec::new(),
            rule_configuration: None,
            probe_entries: HashMap::new(),
            probe_pending: HashSet::new(),
            probe_pins: HashSet::new(),
            probe_fresh: HashSet::new(),
            probe_errors: Vec::new(),
            probe_generation: 0,
            probe_cancel_pending: None,
            probe_signal_mask: None,
        }
    }

    pub fn reconfigure(&mut self, byte_limit: usize, max_candidates: usize) {
        self.byte_limit = byte_limit;
        self.max_candidates = max_candidates;
        self.evict_to_limit();
    }

    pub fn refresh_path(&mut self, path: &str) {
        let directories: Vec<_> = path
            .split(':')
            .take(MAX_PATH_DIRECTORIES)
            .map(|part| {
                if part.is_empty() {
                    PathBuf::from(".")
                } else {
                    PathBuf::from(part)
                }
            })
            .collect();
        if directories == self.path_directories {
            return;
        }
        self.path_directories = directories;
        for directory in self.path_directories.clone() {
            self.request(ScanKey {
                directory,
                prefix: String::new(),
                executable_only: true,
            });
        }
    }

    pub fn load_snapshots(&mut self, home: Option<PathBuf>) {
        if self.snapshots_requested {
            return;
        }
        if let Some(worker) = &self.worker {
            self.snapshots_requested = worker.send(Request::LoadSnapshots { home });
        }
    }

    pub fn filesystem_values(
        &mut self,
        request: &FilesystemRequest,
        working_directory: &Path,
    ) -> (Option<Vec<String>>, bool, bool) {
        let key = FilesystemKey {
            request: request.clone(),
            working_directory: working_directory.to_owned(),
        };
        if self.filesystem_limit_exceeded {
            return (None, false, true);
        }
        let stale = self.filesystem_entries.get(&key).is_none_or(|entry| {
            !self.filesystem_pins.contains(&key)
                && entry.refreshed_at.elapsed() >= FILESYSTEM_CACHE_TTL
        });
        let mut deferred = stale
            && !self.filesystem_pending.contains(&key)
            && self.filesystem_pending.len() >= MAX_FILESYSTEM_CACHE_ENTRIES;
        if stale && !self.filesystem_pending.contains(&key) && !deferred {
            if self.filesystem_entries.len() >= MAX_FILESYSTEM_CACHE_ENTRIES {
                if let Some(oldest) = self
                    .filesystem_entries
                    .iter()
                    .filter(|(key, _)| !self.filesystem_pins.contains(*key))
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone())
                {
                    if let Some(entry) = self.filesystem_entries.remove(&oldest) {
                        self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                        self.filesystem_pins.remove(&oldest);
                    }
                }
            }
            self.filesystem_pending.insert(key.clone());
            let sent = self.worker.as_ref().is_some_and(|worker| {
                worker.send(Request::ResolveFilesystem {
                    key: key.clone(),
                    generation: self.filesystem_generation,
                })
            });
            if !sent {
                self.filesystem_pending.remove(&key);
                deferred = self.worker.is_some();
            }
        }
        // A full in-flight set is backpressure, not a completed empty replay.
        // Keep the menu pending so a later poll can enqueue this key as soon as
        // one of the bounded worker requests finishes.
        let pending = deferred || self.filesystem_pending.contains(&key);
        if let Some(entry) = self.filesystem_entries.get_mut(&key) {
            self.clock = self.clock.wrapping_add(1);
            entry.last_used = self.clock;
            if self.filesystem_pins.len() < MAX_FILESYSTEM_CACHE_ENTRIES
                || self.filesystem_pins.contains(&key)
            {
                self.filesystem_pins.insert(key);
            }
            return (Some(entry.values.clone()), pending, false);
        }
        if pending {
            (None, true, false)
        } else {
            (Some(Vec::new()), false, false)
        }
    }

    pub fn cancel_filesystem_replays(&mut self) {
        self.filesystem_generation = self.worker.as_ref().map_or_else(
            || self.filesystem_generation.wrapping_add(1),
            WorkerClient::cancel_filesystem,
        );
        self.filesystem_pending.clear();
        self.filesystem_pins.clear();
        self.filesystem_limit_exceeded = false;
        self.evict_to_limit();
    }

    pub fn finish_dynamic_replay(&mut self) {
        self.filesystem_pins.clear();
        self.probe_pins.clear();
        self.evict_to_limit();
    }

    pub fn configure_rules(&mut self, paths: Vec<PathBuf>, trusted_key_paths: Vec<PathBuf>) {
        let configuration = (paths, trusted_key_paths);
        if self.rule_configuration.as_ref() == Some(&configuration) {
            return;
        }
        self.rule_configuration = Some(configuration.clone());
        let (paths, trusted_key_paths) = configuration;
        self.rule_generation = self.rule_generation.wrapping_add(1);
        self.rule_catalog_ready = false;
        self.rule_summaries.clear();
        self.rule_pending.clear();
        self.rule_deferred.clear();
        self.rule_catalog_deferred = false;
        for (_, entry) in self.rule_entries.drain() {
            self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
        }
        let generation = self.rule_generation;
        let sent = self.worker.as_ref().is_some_and(|worker| {
            worker.send(Request::DiscoverRules {
                paths,
                trusted_key_paths,
                generation,
            })
        });
        if !sent {
            self.rule_catalog_deferred = self.worker.is_some();
            self.rule_catalog_ready = !self.rule_catalog_deferred;
        }
    }

    pub fn rule_programs(&mut self, command: &str) -> (Option<&[LoadedProgram]>, bool) {
        if command.is_empty() {
            return (None, false);
        }
        if self.rule_catalog_deferred {
            if let Some((paths, trusted_key_paths)) = self.rule_configuration.clone() {
                let sent = self.worker.as_ref().is_some_and(|worker| {
                    worker.send(Request::DiscoverRules {
                        paths,
                        trusted_key_paths,
                        generation: self.rule_generation,
                    })
                });
                if sent {
                    self.rule_catalog_deferred = false;
                } else if self.worker.is_none() {
                    self.rule_catalog_deferred = false;
                    self.rule_catalog_ready = true;
                }
            }
        }
        let mut backpressured = false;
        if !self.rule_entries.contains_key(command) && self.rule_catalog_ready {
            let should_send = if self.rule_deferred.remove(command) {
                true
            } else if self.rule_pending.contains(command) {
                false
            } else {
                if self.rule_pending.len() >= MAX_PENDING_RULE_REQUESTS {
                    if let Some(evicted) = self.rule_deferred.iter().min().cloned() {
                        self.rule_deferred.remove(&evicted);
                        self.rule_pending.remove(&evicted);
                    } else {
                        backpressured = true;
                    }
                }
                !backpressured && self.rule_pending.insert(command.to_owned())
            };
            if should_send {
                let generation = self.rule_generation;
                let sent = self.worker.as_ref().is_some_and(|worker| {
                    worker.send(Request::LoadRules {
                        command: command.to_owned(),
                        generation,
                    })
                });
                if !sent {
                    if self.worker.is_some() {
                        self.rule_deferred.insert(command.to_owned());
                    } else {
                        self.rule_pending.remove(command);
                    }
                }
            }
        }
        let pending =
            backpressured || !self.rule_catalog_ready || self.rule_pending.contains(command);
        if let Some(entry) = self.rule_entries.get_mut(command) {
            self.clock = self.clock.wrapping_add(1);
            entry.last_used = self.clock;
            (Some(&entry.programs), pending)
        } else {
            (None, pending && self.worker.is_some())
        }
    }

    pub fn rule_summaries(&self) -> &[PackSummary] {
        &self.rule_summaries
    }

    pub fn rule_errors(&self) -> &[String] {
        &self.rule_errors
    }

    pub fn record_rule_error(&mut self, error: String) {
        if !self.rule_errors.contains(&error) {
            self.rule_errors.push(error);
            if self.rule_errors.len() > 128 {
                self.rule_errors.drain(..self.rule_errors.len() - 128);
            }
        }
    }

    pub fn background_pending(&self) -> bool {
        self.probe_cancel_pending.is_some()
    }

    pub fn probe_errors(&self) -> &[String] {
        &self.probe_errors
    }

    pub fn cancel_probes(&mut self) {
        if self.probe_pending.is_empty()
            && self.probe_cancel_pending.is_none()
            && self.probe_signal_mask.is_none()
        {
            return;
        }
        self.probe_pending.clear();
        self.probe_pins.clear();
        self.probe_fresh.clear();
        if let Some(worker) = &self.probe_worker {
            self.probe_generation = worker.cancel();
            self.probe_cancel_pending = Some(self.probe_generation);
        } else {
            self.probe_cancel_pending = None;
            self.probe_signal_mask.take();
        }
    }

    pub fn probe_outcome(&mut self, request: &ProbeRequest) -> (Option<ProbeResult>, bool) {
        let (_, pending) = self.probe_values(request);
        let cache_key = ProbeCacheKey::from(request);
        let outcome = self.probe_entries.get(&cache_key).and_then(|entry| {
            (self.probe_pins.contains(&cache_key) || entry.refreshed_at.elapsed() < entry.ttl).then(
                || ProbeResult {
                    status: entry.status,
                    values: entry.values.clone(),
                    truncated: entry.truncated,
                },
            )
        });
        (outcome, pending)
    }

    pub fn probe_values(&mut self, request: &ProbeRequest) -> (Option<&[String]>, bool) {
        let cache_key = ProbeCacheKey::from(request);
        if self.probe_fresh.remove(&cache_key) {
            self.probe_pins.insert(cache_key.clone());
        }
        let stale = !self.probe_pins.contains(&cache_key)
            && self
                .probe_entries
                .get(&cache_key)
                .is_none_or(|entry| entry.refreshed_at.elapsed() >= entry.ttl);
        let mut deferred = false;
        if stale && self.probe_pending.insert(cache_key.clone()) {
            // Bash's process-wide SIGCHLD handler reaps unknown children. Mask
            // it on the Readline thread while a bounded probe is active; the
            // worker also masks it, so waitpid retains the real exit status.
            if self.probe_signal_mask.is_none() {
                self.probe_signal_mask = SignalMaskGuard::block_main_probe_sigchld().ok();
            }
            let sent = self
                .probe_worker
                .as_ref()
                .is_some_and(|worker| worker.send_probe(request.clone(), self.probe_generation));
            if !sent {
                self.probe_pending.remove(&cache_key);
                deferred = self.probe_worker.is_some();
                if self.probe_pending.is_empty() && self.probe_cancel_pending.is_none() {
                    self.probe_signal_mask.take();
                }
            }
        }
        let pending = deferred || self.probe_pending.contains(&cache_key);
        if let Some(entry) = self.probe_entries.get_mut(&cache_key) {
            if stale {
                return (None, pending);
            }
            self.clock = self.clock.wrapping_add(1);
            entry.last_used = self.clock;
            if entry.failed {
                (None, pending)
            } else {
                (Some(&entry.values), pending)
            }
        } else {
            (None, pending && self.probe_worker.is_some())
        }
    }

    pub fn refresh_directory(&mut self, directory: PathBuf) -> ScanKey {
        let generation = self
            .directory_generations
            .entry(directory.clone())
            .or_insert(0);
        *generation = generation.wrapping_add(1);

        // Prefix-specific entries are snapshots of this same directory. Drop
        // all of them at a new prompt so stale paths cannot become ghost text
        // while the fresh broad scan is pending.
        let stale = self
            .entries
            .keys()
            .filter(|key| key.directory == directory && !key.executable_only)
            .cloned()
            .collect::<Vec<_>>();
        for key in stale {
            if let Some(entry) = self.entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
            }
            self.pending.remove(&key);
            self.scan_deferred.remove(&key);
        }

        let key = ScanKey {
            directory,
            prefix: String::new(),
            executable_only: false,
        };
        // A previous generation can still be queued even when it has not
        // produced an entry. Replace its pending marker so the new generation
        // is always enqueued; stale responses must not clear this marker.
        self.pending.remove(&key);
        self.scan_deferred.remove(&key);
        self.enqueue(key.clone(), true);
        key
    }

    pub fn request_directory(&mut self, directory: PathBuf, prefix: &str) -> ScanKey {
        let exact = ScanKey {
            directory: directory.clone(),
            prefix: prefix.to_owned(),
            executable_only: false,
        };
        if self.entries.contains_key(&exact) {
            self.request(exact.clone());
            return exact;
        }

        // A complete scan for a shorter prefix is a lossless superset and can
        // satisfy a refined query without another filesystem traversal.
        if let Some(cached) = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.directory == directory
                    && !key.executable_only
                    && prefix.starts_with(&key.prefix)
                    && !entry.truncated
            })
            .max_by_key(|(key, _)| key.prefix.len())
            .map(|(key, _)| key.clone())
        {
            self.request(cached.clone());
            return cached;
        }

        self.request(exact.clone());
        exact
    }

    fn request(&mut self, key: ScanKey) {
        self.enqueue(key, false);
    }

    fn enqueue(&mut self, key: ScanKey, force: bool) {
        let max_age = if key.executable_only {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(250)
        };
        let stale = force
            || self
                .entries
                .get(&key)
                .is_none_or(|entry| entry.refreshed_at.elapsed() >= max_age);
        if !stale {
            return;
        }
        if self.pending.contains(&key) {
            if !self.scan_deferred.remove(&key) {
                return;
            }
        } else {
            if self.pending.len() >= MAX_PENDING_SCANS {
                let victim = self
                    .scan_deferred
                    .iter()
                    .next()
                    .or_else(|| self.pending.iter().next())
                    .cloned();
                if let Some(victim) = victim {
                    self.pending.remove(&victim);
                    self.scan_deferred.remove(&victim);
                }
            }
            self.pending.insert(key.clone());
        }
        let generation = if key.executable_only {
            0
        } else {
            self.directory_generations
                .get(&key.directory)
                .copied()
                .unwrap_or(0)
        };
        let sent = self.worker.as_ref().is_some_and(|worker| {
            worker.send(Request::Scan {
                key: key.clone(),
                max_candidates: self.max_candidates,
                generation,
            })
        });
        if !sent {
            if self.worker.is_some() {
                self.scan_deferred.insert(key);
            } else {
                self.pending.remove(&key);
            }
        }
    }

    pub fn poll(&mut self) {
        loop {
            let response = match self.worker.as_ref().map(WorkerClient::try_receive) {
                Some(Ok(response)) => response,
                Some(Err(TryRecvError::Empty)) | None => break,
                Some(Err(TryRecvError::Disconnected)) => {
                    self.worker = None;
                    self.pending.clear();
                    self.scan_deferred.clear();
                    self.filesystem_pending.clear();
                    self.filesystem_pins.clear();
                    self.filesystem_limit_exceeded = false;
                    self.rule_pending.clear();
                    self.rule_deferred.clear();
                    self.rule_catalog_deferred = false;
                    self.rule_catalog_ready = true;
                    break;
                }
            };
            match response {
                Response::Scan {
                    key,
                    entries,
                    truncated,
                    generation,
                    completed_at,
                } => {
                    let current_generation = if key.executable_only {
                        0
                    } else {
                        self.directory_generations
                            .get(&key.directory)
                            .copied()
                            .unwrap_or(0)
                    };
                    if generation != current_generation {
                        continue;
                    }
                    self.pending.remove(&key);
                    self.scan_deferred.remove(&key);
                    let approximate_bytes = scan_key_bytes(&key)
                        .saturating_add(std::mem::size_of::<CacheEntry>())
                        .saturating_add(
                            entries
                                .capacity()
                                .saturating_mul(std::mem::size_of::<DirectoryEntry>()),
                        )
                        .saturating_add(
                            entries
                                .iter()
                                .map(|entry| entry.name.capacity())
                                .sum::<usize>(),
                        );
                    self.clock = self.clock.wrapping_add(1);
                    if let Some(previous) = self.entries.insert(
                        key,
                        CacheEntry {
                            entries,
                            truncated,
                            approximate_bytes,
                            last_used: self.clock,
                            refreshed_at: completed_at,
                        },
                    ) {
                        self.used_bytes =
                            self.used_bytes.saturating_sub(previous.approximate_bytes);
                    }
                    self.used_bytes = self.used_bytes.saturating_add(approximate_bytes);
                    self.evict_to_limit();
                }
                Response::Filesystem {
                    key,
                    values,
                    generation,
                    completed_at,
                } => {
                    if generation != self.filesystem_generation {
                        continue;
                    }
                    self.filesystem_pending.remove(&key);
                    let approximate_bytes = filesystem_key_bytes(&key)
                        .saturating_add(std::mem::size_of::<FilesystemCacheEntry>())
                        .saturating_add(
                            values
                                .capacity()
                                .saturating_mul(std::mem::size_of::<String>()),
                        )
                        .saturating_add(values.iter().map(String::capacity).sum::<usize>());
                    self.clock = self.clock.wrapping_add(1);
                    if let Some(previous) = self.filesystem_entries.insert(
                        key.clone(),
                        FilesystemCacheEntry {
                            values,
                            approximate_bytes,
                            last_used: self.clock,
                            refreshed_at: completed_at,
                        },
                    ) {
                        self.used_bytes =
                            self.used_bytes.saturating_sub(previous.approximate_bytes);
                    }
                    self.used_bytes = self.used_bytes.saturating_add(approximate_bytes);
                    self.evict_to_limit();
                    if !self.filesystem_entries.contains_key(&key) {
                        self.filesystem_pins.remove(&key);
                        self.filesystem_limit_exceeded = true;
                    }
                }
                Response::Snapshots {
                    users,
                    groups,
                    passwd_records,
                    group_records,
                    hosts,
                    process_ids,
                    process_names,
                    network_interfaces,
                } => {
                    self.used_bytes = self.used_bytes.saturating_sub(self.snapshot_bytes);
                    self.snapshot_bytes = [
                        &users,
                        &groups,
                        &passwd_records,
                        &group_records,
                        &hosts,
                        &process_ids,
                        &process_names,
                        &network_interfaces,
                    ]
                    .into_iter()
                    .flatten()
                    .map(String::capacity)
                    .sum();
                    self.users = users;
                    self.groups = groups;
                    self.passwd_records = passwd_records;
                    self.group_records = group_records;
                    self.hosts = hosts;
                    self.process_ids = process_ids;
                    self.process_names = process_names;
                    self.network_interfaces = network_interfaces;
                    self.used_bytes = self.used_bytes.saturating_add(self.snapshot_bytes);
                    self.evict_to_limit();
                }
                Response::RuleCatalog {
                    summaries,
                    generation,
                } => {
                    if generation != self.rule_generation {
                        continue;
                    }
                    self.rule_summaries = summaries;
                    self.rule_catalog_ready = true;
                    self.rule_catalog_deferred = false;
                }
                Response::Rules {
                    command,
                    programs,
                    errors,
                    generation,
                } => {
                    if generation != self.rule_generation {
                        continue;
                    }
                    self.rule_pending.remove(&command);
                    self.rule_deferred.remove(&command);
                    let approximate_bytes = approximate_rule_bytes(&programs)
                        .saturating_add(std::mem::size_of::<RuleCacheEntry>())
                        .saturating_add(command.capacity());
                    self.clock = self.clock.wrapping_add(1);
                    if let Some(previous) = self.rule_entries.insert(
                        command,
                        RuleCacheEntry {
                            programs,
                            approximate_bytes,
                            last_used: self.clock,
                        },
                    ) {
                        self.used_bytes =
                            self.used_bytes.saturating_sub(previous.approximate_bytes);
                    }
                    self.used_bytes = self.used_bytes.saturating_add(approximate_bytes);
                    self.rule_errors.extend(errors);
                    if self.rule_errors.len() > 128 {
                        self.rule_errors.drain(..self.rule_errors.len() - 128);
                    }
                    self.evict_to_limit();
                }
            }
        }
        self.poll_probe_responses();
    }

    fn poll_probe_responses(&mut self) {
        loop {
            let response = match self.probe_worker.as_ref().map(ProbeClient::try_receive) {
                Some(Ok(response)) => response,
                Some(Err(TryRecvError::Empty)) | None => break,
                Some(Err(TryRecvError::Disconnected)) => {
                    self.probe_worker = None;
                    self.probe_pending.clear();
                    self.probe_pins.clear();
                    self.probe_fresh.clear();
                    self.probe_cancel_pending = None;
                    self.probe_signal_mask.take();
                    break;
                }
            };
            match response {
                ProbeResponse::Outcome {
                    request,
                    generation,
                    status,
                    values,
                    truncated,
                    error,
                    completed_at,
                } => {
                    if generation != self.probe_generation {
                        continue;
                    }
                    let request = *request;
                    let cache_key = ProbeCacheKey::from(&request);
                    self.probe_pending.remove(&cache_key);
                    if self.probe_pending.is_empty() && self.probe_cancel_pending.is_none() {
                        self.probe_signal_mask.take();
                    }
                    let failed = error.is_some() || status != 0;
                    if let Some(error) = error {
                        self.probe_errors
                            .push(format!("{}: {error}", request.probe_id));
                        if self.probe_errors.len() > 128 {
                            self.probe_errors.drain(..self.probe_errors.len() - 128);
                        }
                    }
                    let approximate_bytes = probe_key_bytes(&cache_key)
                        .saturating_add(std::mem::size_of::<ProbeCacheEntry>())
                        .saturating_add(
                            values
                                .capacity()
                                .saturating_mul(std::mem::size_of::<String>()),
                        )
                        .saturating_add(values.iter().map(String::capacity).sum::<usize>());
                    self.clock = self.clock.wrapping_add(1);
                    self.probe_fresh.insert(cache_key.clone());
                    if let Some(previous) = self.probe_entries.insert(
                        cache_key,
                        ProbeCacheEntry {
                            values,
                            status,
                            truncated,
                            failed,
                            refreshed_at: completed_at,
                            ttl: if failed {
                                Duration::from_secs(10)
                            } else {
                                Duration::from_millis(request.cache_ttl_ms.into())
                            },
                            approximate_bytes,
                            last_used: self.clock,
                        },
                    ) {
                        self.used_bytes =
                            self.used_bytes.saturating_sub(previous.approximate_bytes);
                    }
                    self.used_bytes = self.used_bytes.saturating_add(approximate_bytes);
                    self.evict_to_limit();
                }
                ProbeResponse::Cancelled { generation } => {
                    if self.probe_cancel_pending == Some(generation) {
                        self.probe_cancel_pending = None;
                        if self.probe_pending.is_empty() {
                            self.probe_signal_mask.take();
                        }
                    }
                }
            }
        }
    }

    pub fn directory_entries(&mut self, key: &ScanKey) -> Option<(&[DirectoryEntry], bool, bool)> {
        let refreshing = self.pending.contains(key);
        let entry = self.entries.get_mut(key)?;
        self.clock = self.clock.wrapping_add(1);
        entry.last_used = self.clock;
        Some((&entry.entries, entry.truncated, refreshing))
    }

    pub fn for_each_command(&mut self, query: &str, mut visitor: impl FnMut(&str) -> bool) -> bool {
        let directories = self.path_directories.clone();
        let mut pending = false;
        for directory in directories {
            let broad = ScanKey {
                directory: directory.clone(),
                prefix: String::new(),
                executable_only: true,
            };
            self.request(broad.clone());
            let key = match self.entries.get(&broad) {
                Some(entry) if !entry.truncated => broad,
                _ if !query.is_empty() => {
                    let refined = ScanKey {
                        directory,
                        prefix: query.to_owned(),
                        executable_only: true,
                    };
                    self.request(refined.clone());
                    refined
                }
                _ => broad,
            };
            if let Some((entries, _, refreshing)) = self.directory_entries(&key) {
                pending |= refreshing;
                for entry in entries {
                    if !visitor(&entry.name) {
                        return pending;
                    }
                }
            } else {
                pending |= self.worker.is_some();
            }
        }
        pending
    }

    pub fn command_available(&mut self, name: &str) -> Option<bool> {
        let directories = self.path_directories.clone();
        let mut complete = true;
        for directory in directories {
            let broad = ScanKey {
                directory: directory.clone(),
                prefix: String::new(),
                executable_only: true,
            };
            self.request(broad.clone());
            if self
                .entries
                .get(&broad)
                .is_some_and(|entry| entry.entries.iter().any(|item| item.name == name))
            {
                return Some(true);
            }
            let broad_complete = self
                .entries
                .get(&broad)
                .is_some_and(|entry| !entry.truncated && !self.pending.contains(&broad));
            if broad_complete {
                continue;
            }
            let refined = ScanKey {
                directory,
                prefix: name.to_owned(),
                executable_only: true,
            };
            self.request(refined.clone());
            if self
                .entries
                .get(&refined)
                .is_some_and(|entry| entry.entries.iter().any(|item| item.name == name))
            {
                return Some(true);
            }
            if !self
                .entries
                .get(&refined)
                .is_some_and(|entry| !entry.truncated && !self.pending.contains(&refined))
            {
                complete = false;
            }
        }
        complete.then_some(false)
    }

    pub fn command_known(&self, name: &str) -> Option<bool> {
        let mut complete = true;
        for directory in &self.path_directories {
            let key = ScanKey {
                directory: directory.clone(),
                prefix: String::new(),
                executable_only: true,
            };
            match self.entries.get(&key) {
                Some(entry) if entry.entries.iter().any(|item| item.name == name) => {
                    return Some(true);
                }
                Some(_) if self.pending.contains(&key) => complete = false,
                Some(entry) if entry.truncated => complete = false,
                Some(_) => {}
                None => complete = false,
            }
        }
        complete.then_some(false)
    }

    pub fn scan_available(&self) -> bool {
        self.worker.is_some()
    }

    pub fn users(&self) -> &[String] {
        &self.users
    }

    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    pub fn passwd_records(&self) -> &[String] {
        &self.passwd_records
    }

    pub fn group_records(&self) -> &[String] {
        &self.group_records
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn process_ids(&self) -> &[String] {
        &self.process_ids
    }

    pub fn process_names(&self) -> &[String] {
        &self.process_names
    }

    pub fn network_interfaces(&self) -> &[String] {
        &self.network_interfaces
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    pub fn entry_count(&self) -> usize {
        self.entries.values().map(|entry| entry.entries.len()).sum()
    }

    pub fn rule_entry_count(&self) -> usize {
        self.rule_entries
            .values()
            .map(|entry| entry.programs.len())
            .sum()
    }

    pub fn stop(&mut self) {
        if let Some(mut worker) = self.worker.take() {
            worker.stop();
        }
        if let Some(mut worker) = self.probe_worker.take() {
            worker.stop();
        }
        self.filesystem_pending.clear();
        self.filesystem_pins.clear();
        self.filesystem_limit_exceeded = false;
        self.probe_pending.clear();
        self.probe_pins.clear();
        self.probe_fresh.clear();
        self.probe_cancel_pending = None;
        self.probe_signal_mask.take();
    }

    fn evict_to_limit(&mut self) {
        while self.entries.len() > MAX_DIRECTORY_CACHE_ENTRIES {
            let Some(key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = self.entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
            }
        }
        while self.filesystem_entries.len() > MAX_FILESYSTEM_CACHE_ENTRIES {
            let Some(key) = self
                .filesystem_entries
                .iter()
                .filter(|(key, _)| !self.filesystem_pins.contains(*key))
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = self.filesystem_entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                self.filesystem_pins.remove(&key);
            }
        }
        while self.rule_entries.len() > MAX_RULE_CACHE_ENTRIES {
            let Some(key) = self
                .rule_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = self.rule_entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
            }
        }
        while self.probe_entries.len() > MAX_PROBE_CACHE_ENTRIES {
            let Some(key) = self
                .probe_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = self.probe_entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                self.probe_pins.remove(&key);
                self.probe_fresh.remove(&key);
            }
        }
        while self.used_bytes > self.byte_limit
            && self
                .entries
                .len()
                .saturating_add(self.filesystem_entries.len())
                .saturating_add(self.rule_entries.len())
                .saturating_add(self.probe_entries.len())
                > 0
        {
            let oldest_directory = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, entry)| (key.clone(), entry.last_used));
            let oldest_filesystem = self
                .filesystem_entries
                .iter()
                .filter(|(key, _)| !self.filesystem_pins.contains(*key))
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, entry)| (key.clone(), entry.last_used));
            let oldest_rule = self
                .rule_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, entry)| (key.clone(), entry.last_used));
            let oldest_probe = self
                .probe_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, entry)| (key.clone(), entry.last_used));
            let Some(minimum_clock) = oldest_directory
                .as_ref()
                .map(|(_, clock)| *clock)
                .into_iter()
                .chain(oldest_filesystem.as_ref().map(|(_, clock)| *clock))
                .chain(oldest_rule.as_ref().map(|(_, clock)| *clock))
                .chain(oldest_probe.as_ref().map(|(_, clock)| *clock))
                .min()
            else {
                break;
            };
            if oldest_probe
                .as_ref()
                .is_some_and(|(_, clock)| *clock == minimum_clock)
            {
                let key = oldest_probe.expect("oldest probe exists").0;
                if let Some(entry) = self.probe_entries.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                    self.probe_pins.remove(&key);
                    self.probe_fresh.remove(&key);
                }
            } else if oldest_filesystem
                .as_ref()
                .is_some_and(|(_, clock)| *clock == minimum_clock)
            {
                let key = oldest_filesystem.expect("oldest filesystem entry exists").0;
                if let Some(entry) = self.filesystem_entries.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                    self.filesystem_pins.remove(&key);
                }
            } else if oldest_rule
                .as_ref()
                .is_some_and(|(_, clock)| *clock == minimum_clock)
            {
                let command = oldest_rule.expect("oldest rule exists").0;
                if let Some(entry) = self.rule_entries.remove(&command) {
                    self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                }
            } else if let Some((key, _)) = oldest_directory {
                if let Some(entry) = self.entries.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                }
            } else {
                break;
            }
        }
    }
}

fn probe_worker_loop(
    requests: Receiver<ProbeWorkerRequest>,
    responses: Sender<ProbeResponse>,
    stop: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
) {
    let _signal_mask = SignalMaskGuard::block_sigchld().ok();
    let mut probes = ProbeSupervisor::default();
    let mut probe_generations = HashMap::<ProbeCacheKey, u64>::new();
    let mut observed_generation = 0_u64;
    loop {
        if stop.load(Ordering::Acquire) {
            probes.cancel_all();
            break;
        }
        let current_generation = generation.load(Ordering::Acquire);
        if current_generation != observed_generation {
            probes.cancel_all();
            probe_generations.clear();
            observed_generation = current_generation;
            if responses
                .send(ProbeResponse::Cancelled {
                    generation: current_generation,
                })
                .is_err()
            {
                break;
            }
        }
        let request = if probes.has_work() {
            match requests.recv_timeout(Duration::from_millis(10)) {
                Ok(request) => Some(request),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match requests.recv() {
                Ok(request) => Some(request),
                Err(_) => break,
            }
        };
        if stop.load(Ordering::Acquire) {
            probes.cancel_all();
            break;
        }
        if let Some(request) = request {
            match request {
                ProbeWorkerRequest::Run {
                    request,
                    generation,
                } if generation == observed_generation => {
                    let request = *request;
                    let cache_key = ProbeCacheKey::from(&request);
                    if probes.submit(request.clone()) {
                        probe_generations.insert(cache_key, generation);
                    } else if responses
                        .send(ProbeResponse::Outcome {
                            request: Box::new(request),
                            generation,
                            status: 1,
                            values: Vec::new(),
                            truncated: false,
                            error: Some("probe queue rejected the request".into()),
                            completed_at: Instant::now(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                ProbeWorkerRequest::Run { .. } | ProbeWorkerRequest::Wake => {}
                ProbeWorkerRequest::Stop => {
                    probes.cancel_all();
                    break;
                }
            }
        }
        for outcome in probes.poll() {
            let cache_key = ProbeCacheKey::from(&outcome.request);
            let Some(generation) = probe_generations.remove(&cache_key) else {
                continue;
            };
            if responses
                .send(ProbeResponse::Outcome {
                    request: Box::new(outcome.request),
                    generation,
                    status: outcome.status,
                    values: outcome.values,
                    truncated: outcome.truncated,
                    error: outcome.error,
                    completed_at: outcome.completed_at,
                })
                .is_err()
            {
                return;
            }
        }
    }
}

fn worker_loop(
    requests: Receiver<Request>,
    responses: Sender<Response>,
    stop: Arc<AtomicBool>,
    filesystem_generation: Arc<AtomicU64>,
) {
    // Never let Bash's process-wide SIGCHLD handler run on a Rust worker.
    let _signal_mask = SignalMaskGuard::block_sigchld().ok();
    let mut rules = RuleStore::default();
    let mut deferred = VecDeque::new();
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let request = if let Some(request) = deferred.pop_front() {
            request
        } else {
            match requests.recv() {
                Ok(request) => request,
                Err(_) => break,
            }
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        match request {
            Request::Scan {
                mut key,
                mut max_candidates,
                mut generation,
            } => {
                // Prompt refreshes can supersede the same scan faster than
                // a slow filesystem responds. Coalesce matching work from
                // both bounded queues while retaining unrelated FIFO order.
                let mut retained = VecDeque::with_capacity(deferred.len());
                while let Some(queued) = deferred.pop_front() {
                    match queued {
                        Request::Scan {
                            key: queued_key,
                            max_candidates: queued_max,
                            generation: queued_generation,
                        } if queued_key == key => {
                            if queued_generation >= generation {
                                key = queued_key;
                                max_candidates = queued_max;
                                generation = queued_generation;
                            }
                        }
                        Request::Stop => return,
                        other => retained.push_back(other),
                    }
                }
                deferred = retained;
                while deferred.len() < MAX_WORKER_REQUESTS {
                    let Ok(queued) = requests.try_recv() else {
                        break;
                    };
                    match queued {
                        Request::Scan {
                            key: queued_key,
                            max_candidates: queued_max,
                            generation: queued_generation,
                        } if queued_key == key => {
                            if queued_generation >= generation {
                                key = queued_key;
                                max_candidates = queued_max;
                                generation = queued_generation;
                            }
                        }
                        Request::Stop => return,
                        other => deferred.push_back(other),
                    }
                }
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let (entries, truncated) = scan_directory(&key, max_candidates);
                if responses
                    .send(Response::Scan {
                        key,
                        entries,
                        truncated,
                        generation,
                        completed_at: Instant::now(),
                    })
                    .is_err()
                {
                    break;
                }
            }
            Request::LoadSnapshots { home } => {
                let (users, passwd_records) = load_users();
                let (groups, group_records) = load_groups();
                let hosts = load_hosts(home.as_deref());
                let (process_ids, process_names) = load_processes();
                let network_interfaces = load_network_interfaces();
                if responses
                    .send(Response::Snapshots {
                        users,
                        groups,
                        passwd_records,
                        group_records,
                        hosts,
                        process_ids,
                        process_names,
                        network_interfaces,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Request::ResolveFilesystem { key, generation } => {
                if generation != filesystem_generation.load(Ordering::Acquire) {
                    continue;
                }
                let values = super::provider::resolve_filesystem_request(
                    &key.request,
                    &key.working_directory,
                );
                if responses
                    .send(Response::Filesystem {
                        key,
                        values,
                        generation,
                        completed_at: Instant::now(),
                    })
                    .is_err()
                {
                    break;
                }
            }
            Request::DiscoverRules {
                paths,
                trusted_key_paths,
                generation,
            } => {
                rules = RuleStore::discover(&paths, &trusted_key_paths);
                if responses
                    .send(Response::RuleCatalog {
                        summaries: rules.summaries().to_vec(),
                        generation,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Request::LoadRules {
                command,
                generation,
            } => {
                let (programs, errors) = rules.load_command(&command);
                if responses
                    .send(Response::Rules {
                        command,
                        programs,
                        errors,
                        generation,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Request::Stop => break,
        }
    }
}

fn approximate_rule_bytes(programs: &[LoadedProgram]) -> usize {
    programs.iter().fold(0_usize, |total, loaded| {
        let program = &loaded.program;
        let metadata = loaded
            .pack_name
            .capacity()
            .saturating_add(loaded.pack_version.capacity())
            .saturating_add(program.canonical_name.capacity())
            .saturating_add(program.source_path.capacity())
            .saturating_add(program.source_commit.capacity())
            .saturating_add(program.license.capacity())
            .saturating_add(
                program
                    .registrations
                    .iter()
                    .map(|value| value.capacity())
                    .sum::<usize>(),
            )
            .saturating_add(
                loaded
                    .required_commands
                    .iter()
                    .map(|value| std::mem::size_of::<String>() + value.capacity())
                    .sum::<usize>(),
            );
        let rules = program.static_rules.iter().fold(0_usize, |size, rule| {
            size.saturating_add(std::mem::size_of_val(rule))
                .saturating_add(
                    rule.when.len() * std::mem::size_of::<crate::rules::ir::PredicateOp>(),
                )
                .saturating_add(rule.candidates.iter().fold(
                    0_usize,
                    |candidate_size, candidate| {
                        candidate_size
                            .saturating_add(std::mem::size_of_val(candidate))
                            .saturating_add(candidate.value.capacity())
                            .saturating_add(candidate.display.capacity())
                            .saturating_add(
                                candidate.description.as_ref().map_or(0, String::capacity),
                            )
                    },
                ))
        });
        let probes = program.probes.iter().fold(0_usize, |size, probe| {
            size.saturating_add(std::mem::size_of_val(probe))
                .saturating_add(probe.id.capacity())
                .saturating_add(probe.executable.capacity())
                .saturating_add(
                    probe
                        .arguments
                        .iter()
                        .map(|value| value.capacity())
                        .sum::<usize>(),
                )
        });
        let scripts = program
            .scripts
            .iter()
            .map(crate::rules::script::ScriptModule::approximate_bytes)
            .sum::<usize>();
        total
            .saturating_add(std::mem::size_of_val(loaded))
            .saturating_add(metadata)
            .saturating_add(rules)
            .saturating_add(probes)
            .saturating_add(scripts)
    })
}

fn scan_directory(key: &ScanKey, max_candidates: usize) -> (Vec<DirectoryEntry>, bool) {
    let Ok(directory) = fs::read_dir(&key.directory) else {
        return (Vec::new(), false);
    };
    let show_hidden = key.prefix.starts_with('.');
    let mut ranked = Vec::new();
    let mut matching_count = 0_usize;

    for item in directory.flatten() {
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let Some((_, score)) = match_score(&key.prefix, &name) else {
            continue;
        };

        let followed = fs::metadata(item.path()).ok();
        let is_directory = followed.as_ref().is_some_and(|metadata| metadata.is_dir());
        let executable = !is_directory
            && followed.is_some_and(|metadata| metadata.permissions().mode() & 0o111 != 0);
        if key.executable_only && !executable {
            continue;
        }

        matching_count = matching_count.saturating_add(1);
        ranked.push((
            score,
            DirectoryEntry {
                name,
                kind: if is_directory {
                    EntryKind::Directory
                } else if executable {
                    EntryKind::Executable
                } else {
                    EntryKind::File
                },
            },
        ));
        if ranked.len() >= max_candidates.saturating_mul(2).max(2) {
            ranked.sort_unstable_by(|left, right| {
                right
                    .0
                    .cmp(&left.0)
                    .then_with(|| left.1.name.cmp(&right.1.name))
            });
            ranked.truncate(max_candidates);
        }
    }

    ranked.sort_unstable_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.name.cmp(&right.1.name))
    });
    ranked.truncate(max_candidates);
    (
        ranked.into_iter().map(|(_, entry)| entry).collect(),
        matching_count > max_candidates,
    )
}

fn load_processes() -> (Vec<String>, Vec<String>) {
    let Ok(entries) = fs::read_dir("/proc") else {
        return (Vec::new(), Vec::new());
    };
    let mut processes = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let pid = name.parse::<u32>().ok()?;
            Some((pid, entry.path()))
        })
        .take(16_384)
        .collect::<Vec<_>>();
    processes.sort_unstable_by_key(|(pid, _)| *pid);
    processes.truncate(4096);
    let mut ids = Vec::with_capacity(processes.len());
    let mut names = Vec::with_capacity(processes.len());
    for (pid, path) in processes {
        ids.push(pid.to_string());
        let name = fs::File::open(path.join("comm"))
            .ok()
            .and_then(|file| {
                let mut data = Vec::new();
                file.take(4096).read_to_end(&mut data).ok()?;
                Some(String::from_utf8_lossy(&data).trim().to_owned())
            })
            .filter(|name| !name.chars().any(char::is_control))
            .unwrap_or_default();
        names.push(name);
    }
    (ids, names)
}

fn load_network_interfaces() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut interfaces = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.is_empty() && !name.chars().any(char::is_control))
        .take(1024)
        .collect::<Vec<_>>();
    interfaces.sort_unstable();
    interfaces.dedup();
    interfaces
}

fn load_users() -> (Vec<String>, Vec<String>) {
    load_account_records("/etc/passwd")
}

fn load_groups() -> (Vec<String>, Vec<String>) {
    load_account_records("/etc/group")
}

fn read_bounded_regular_file(path: &Path, byte_limit: usize) -> Option<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > byte_limit as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(byte_limit as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= byte_limit).then_some(bytes)
}

fn load_account_records(path: &str) -> (Vec<String>, Vec<String>) {
    let Some(bytes) = read_bounded_regular_file(Path::new(path), 1024 * 1024) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(contents) = String::from_utf8(bytes) else {
        return (Vec::new(), Vec::new());
    };
    let mut names = Vec::new();
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for line in contents.lines().take(4096) {
        if line.len() <= 64 * 1024 {
            if let Some((name, _)) = line.split_once(':') {
                if !name.is_empty()
                    && !name.chars().any(char::is_control)
                    && seen.insert(name.to_owned())
                {
                    names.push(name.to_owned());
                    records.push(line.to_owned());
                }
            }
        }
    }
    (names, records)
}

const MAX_HOST_FILES: usize = 128;
const MAX_HOST_LINES: usize = 16_384;
const MAX_HOST_BYTES: usize = 4 * 1024 * 1024;

struct HostCollector<'a> {
    home: Option<&'a Path>,
    hosts: Vec<String>,
    seen: HashSet<String>,
    visited: HashSet<PathBuf>,
    files: usize,
    lines: usize,
    bytes: usize,
}

impl<'a> HostCollector<'a> {
    fn new(home: Option<&'a Path>) -> Self {
        Self {
            home,
            hosts: Vec::new(),
            seen: HashSet::new(),
            visited: HashSet::new(),
            files: 0,
            lines: 0,
            bytes: 0,
        }
    }

    fn add(&mut self, host: &str) {
        let host = host.trim();
        if !host.is_empty()
            && host.len() <= 4096
            && !host.chars().any(char::is_control)
            && self.seen.insert(host.to_owned())
        {
            self.hosts.push(host.to_owned());
        }
    }

    fn read_file(&mut self, path: &Path) -> Option<String> {
        if self.files >= MAX_HOST_FILES || self.lines >= MAX_HOST_LINES {
            return None;
        }
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !self.visited.insert(canonical) {
            return None;
        }
        let remaining = MAX_HOST_BYTES.saturating_sub(self.bytes).min(1024 * 1024);
        let bytes = read_bounded_regular_file(path, remaining)?;
        let length = bytes.len();
        let contents = String::from_utf8(bytes).ok()?;
        self.files += 1;
        self.bytes += length;
        Some(contents)
    }

    fn read_hosts(&mut self, path: &Path) {
        let Some(contents) = self.read_file(path) else {
            return;
        };
        for line in contents.lines() {
            if self.lines >= MAX_HOST_LINES {
                break;
            }
            self.lines += 1;
            let line = line.split('#').next().unwrap_or_default();
            for host in line.split_whitespace().skip(1) {
                self.add(host);
            }
        }
    }

    fn read_ssh_config(&mut self, path: &Path, depth: usize) {
        if depth >= 8 {
            return;
        }
        let Some(contents) = self.read_file(path) else {
            return;
        };
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for line in contents.lines() {
            if self.lines >= MAX_HOST_LINES {
                break;
            }
            self.lines += 1;
            let line = line.split('#').next().unwrap_or_default();
            let mut words = line.split_whitespace();
            let Some(keyword) = words.next() else {
                continue;
            };
            if keyword.eq_ignore_ascii_case("host") {
                for host in words {
                    let host = host.trim_matches(['\'', '"']);
                    if !host.contains(['*', '?', '!']) {
                        self.add(host);
                    }
                }
            } else if keyword.eq_ignore_ascii_case("include") {
                let patterns = words.map(str::to_owned).collect::<Vec<_>>();
                for pattern in patterns {
                    for include in expand_ssh_include(&pattern, base, self.home) {
                        self.read_ssh_config(&include, depth + 1);
                    }
                }
            }
        }
    }

    fn read_known_hosts(&mut self, path: &Path) {
        let Some(contents) = self.read_file(path) else {
            return;
        };
        for line in contents.lines() {
            if self.lines >= MAX_HOST_LINES {
                break;
            }
            self.lines += 1;
            let mut words = line.split_whitespace();
            let Some(mut field) = words.next() else {
                continue;
            };
            if field.starts_with('@') {
                let Some(next) = words.next() else {
                    continue;
                };
                field = next;
            }
            if field.starts_with('|') {
                continue;
            }
            for host in field.split(',') {
                let host = if let Some(bracketed) = host.strip_prefix('[') {
                    bracketed
                        .split_once("]:")
                        .map_or(bracketed, |(host, _)| host)
                } else {
                    host.split(':').next().unwrap_or(host)
                };
                if !host.contains(['*', '?', '!']) {
                    self.add(host);
                }
            }
        }
    }
}

fn expand_ssh_include(pattern: &str, base: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let pattern = pattern.trim_matches(['\'', '"']);
    let path = if let Some(relative) = pattern.strip_prefix("~/") {
        home.map_or_else(|| base.join(pattern), |home| home.join(relative))
    } else {
        let path = Path::new(pattern);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    };
    if !pattern.contains(['*', '?', '[']) {
        return vec![path];
    }
    let mut paths = vec![PathBuf::new()];
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => paths = vec![PathBuf::from("/")],
            Component::Prefix(prefix) => paths = vec![PathBuf::from(prefix.as_os_str())],
            Component::CurDir => {}
            Component::ParentDir => {
                for path in &mut paths {
                    path.push("..");
                }
            }
            Component::Normal(component) => {
                let component = component.to_string_lossy();
                if component.contains(['*', '?', '[']) {
                    let mut expanded = Vec::new();
                    for parent in &paths {
                        let Ok(entries) = fs::read_dir(parent) else {
                            continue;
                        };
                        let mut names = Vec::new();
                        for name in entries
                            .flatten()
                            .filter_map(|entry| entry.file_name().into_string().ok())
                            .filter(|name| ssh_glob_match(component.as_bytes(), name.as_bytes()))
                        {
                            names.push(name);
                            if names.len() >= MAX_HOST_FILES * 2 {
                                names.sort_unstable();
                                names.truncate(MAX_HOST_FILES);
                            }
                        }
                        names.sort_unstable();
                        names.truncate(MAX_HOST_FILES);
                        for name in names {
                            if expanded.len() >= MAX_HOST_FILES {
                                break;
                            }
                            expanded.push(parent.join(name));
                        }
                    }
                    paths = expanded;
                } else {
                    for path in &mut paths {
                        path.push(component.as_ref());
                    }
                }
            }
        }
        if paths.len() > MAX_HOST_FILES {
            paths.truncate(MAX_HOST_FILES);
        }
    }
    paths
}

fn ssh_glob_match(pattern: &[u8], value: &[u8]) -> bool {
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let mut next = vec![false; value.len() + 1];
        match pattern[index] {
            b'*' => {
                next[0] = row[0];
                for position in 1..=value.len() {
                    next[position] = row[position] || next[position - 1];
                }
            }
            b'?' => next[1..].copy_from_slice(&row[..value.len()]),
            b'[' => {
                if let Some(offset) = pattern[index + 1..]
                    .iter()
                    .position(|candidate| *candidate == b']')
                {
                    let close = index + 1 + offset;
                    let class = &pattern[index + 1..close];
                    for position in 1..=value.len() {
                        next[position] = row[position - 1] && class.contains(&value[position - 1]);
                    }
                    index = close;
                }
            }
            byte => {
                for position in 1..=value.len() {
                    next[position] = row[position - 1] && value[position - 1] == byte;
                }
            }
        }
        row = next;
        index += 1;
    }
    row[value.len()]
}

fn load_hosts(home: Option<&Path>) -> Vec<String> {
    let mut collector = HostCollector::new(home);
    collector.read_hosts(Path::new("/etc/hosts"));
    collector.read_ssh_config(Path::new("/etc/ssh/ssh_config"), 0);
    if let Some(home) = home {
        collector.read_ssh_config(&home.join(".ssh/config"), 0);
    }
    collector.read_known_hosts(Path::new("/etc/ssh/ssh_known_hosts"));
    if let Some(home) = home {
        collector.read_known_hosts(&home.join(".ssh/known_hosts"));
    }
    collector.hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn host_snapshot_follows_bounded_ssh_includes_in_source_order() {
        let root = std::env::temp_dir().join(format!(
            "bashlume-hosts-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let ssh = root.join(".ssh");
        fs::create_dir_all(ssh.join("conf.d")).unwrap();
        fs::write(
            ssh.join("config"),
            "Host first\nInclude conf.d/*.conf\nHost last\n",
        )
        .unwrap();
        fs::write(ssh.join("conf.d/10.conf"), "Host included-one\n").unwrap();
        fs::write(ssh.join("conf.d/20.conf"), "Host included-two\n").unwrap();
        fs::write(
            ssh.join("known_hosts"),
            "[bracketed.example]:2222 ssh-ed25519 key\n",
        )
        .unwrap();

        let hosts = load_hosts(Some(&root));
        let positions = [
            "first",
            "included-one",
            "included-two",
            "last",
            "bracketed.example",
        ]
        .map(|host| {
            hosts
                .iter()
                .position(|candidate| candidate == host)
                .unwrap()
        });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_snapshot_has_a_fixed_directory_bound() {
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let path = (0..(MAX_PATH_DIRECTORIES + 32))
            .map(|index| format!("/snapshot/{index}"))
            .collect::<Vec<_>>()
            .join(":");
        cache.refresh_path(&path);
        assert_eq!(cache.path_directories.len(), MAX_PATH_DIRECTORIES);
    }

    #[test]
    fn process_and_network_snapshots_are_bounded_and_deterministic() {
        let (ids, names) = load_processes();
        assert!(ids.len() <= 4096);
        assert_eq!(ids.len(), names.len());
        assert!(ids.iter().all(|pid| pid.parse::<u32>().is_ok()));
        assert!(
            ids.windows(2)
                .all(|pair| { pair[0].parse::<u32>().unwrap() < pair[1].parse::<u32>().unwrap() })
        );
        let interfaces = load_network_interfaces();
        assert!(interfaces.len() <= 1024);
        assert!(interfaces.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn directory_scan_keeps_best_matches_and_marks_truncation() {
        let root = std::env::temp_dir().join(format!("bashlume-worker-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for name in ["alpha", "alpine", "alphabet", "beta"] {
            let mut file = fs::File::create(root.join(name)).unwrap();
            writeln!(file, "test").unwrap();
        }
        let key = ScanKey {
            directory: root.clone(),
            prefix: "al".into(),
            executable_only: false,
        };
        let (entries, truncated) = scan_directory(&key, 2);
        assert_eq!(entries.len(), 2);
        assert!(truncated);
        assert!(entries.iter().all(|entry| entry.name.starts_with("al")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn filesystem_requests_are_resolved_only_by_the_worker_and_replayed() {
        let root =
            std::env::temp_dir().join(format!("bashlume-filesystem-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("data"), "first\nsecond\n").unwrap();
        let request = FilesystemRequest {
            request_id: "filesystem:test".into(),
            kind: crate::rules::vm::FilesystemRequestKind::Read,
            dialect: crate::rules::script::ScriptDialect::Fish,
            path: "data".into(),
            operator: None,
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let (values, pending, limited) = cache.filesystem_values(&request, &root);
        assert!(values.is_none());
        assert!(pending);
        assert!(!limited);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            cache.poll();
            let (values, pending, limited) = cache.filesystem_values(&request, &root);
            assert!(!limited);
            if let Some(values) = values {
                assert_eq!(values, ["first", "second"]);
                assert!(!pending);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }

        let key = FilesystemKey {
            request: request.clone(),
            working_directory: root.clone(),
        };
        cache.filesystem_entries.get_mut(&key).unwrap().refreshed_at =
            Instant::now() - FILESYSTEM_CACHE_TTL - Duration::from_millis(1);
        let (values, pending, limited) = cache.filesystem_values(&request, &root);
        assert!(!limited);
        assert_eq!(values.unwrap(), ["first", "second"]);
        assert!(!pending, "the active evaluation must pin a coherent replay");
        cache.cancel_filesystem_replays();
        let (values, pending, limited) = cache.filesystem_values(&request, &root);
        assert!(!limited);
        assert_eq!(values.unwrap(), ["first", "second"]);
        assert!(pending, "a new evaluation may refresh the expired replay");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn filesystem_cancellation_ignores_an_obsolete_generation() {
        let root = std::env::temp_dir().join(format!(
            "bashlume-filesystem-generation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("old"), "obsolete\n").unwrap();
        fs::write(root.join("new"), "current\n").unwrap();
        let request = |id: &str, path: &str| FilesystemRequest {
            request_id: id.into(),
            kind: crate::rules::vm::FilesystemRequestKind::Read,
            dialect: crate::rules::script::ScriptDialect::Fish,
            path: path.into(),
            operator: None,
        };
        let old = request("filesystem:old", "old");
        let new = request("filesystem:new", "new");
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        assert!(cache.filesystem_values(&old, &root).1);
        cache.cancel_filesystem_replays();
        assert!(cache.filesystem_values(&new, &root).1);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            cache.poll();
            let (values, pending, limited) = cache.filesystem_values(&new, &root);
            assert!(!limited);
            if let Some(values) = values {
                assert_eq!(values, ["current"]);
                assert!(!pending);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !cache
                .filesystem_entries
                .keys()
                .any(|key| key.request == old)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn full_worker_queue_keeps_retries_bounded_and_pending() {
        let (request_tx, _request_rx) = mpsc::sync_channel(0);
        let (_response_tx, response_rx) = mpsc::channel();
        let worker = WorkerClient {
            requests: Some(request_tx),
            responses: response_rx,
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
            filesystem_generation: Arc::new(AtomicU64::new(0)),
        };
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        cache.worker = Some(worker);
        for index in 0..(MAX_PENDING_SCANS * 2) {
            cache.enqueue(
                ScanKey {
                    directory: PathBuf::from(format!("/snapshot/{index}")),
                    prefix: String::new(),
                    executable_only: false,
                },
                true,
            );
        }
        assert_eq!(cache.pending.len(), MAX_PENDING_SCANS);
        assert_eq!(cache.scan_deferred.len(), MAX_PENDING_SCANS);

        for index in 0..(MAX_PENDING_RULE_REQUESTS * 2) {
            assert!(cache.rule_programs(&format!("command-{index}")).1);
        }
        assert_eq!(cache.rule_pending.len(), MAX_PENDING_RULE_REQUESTS);
        assert_eq!(cache.rule_deferred.len(), MAX_PENDING_RULE_REQUESTS);

        let request = FilesystemRequest {
            request_id: "filesystem:full-worker-queue".into(),
            kind: crate::rules::vm::FilesystemRequestKind::Test,
            dialect: crate::rules::script::ScriptDialect::Bash,
            path: "deferred".into(),
            operator: Some("-e".into()),
        };
        let (values, pending, limited) = cache.filesystem_values(&request, Path::new("/tmp"));
        assert!(values.is_none());
        assert!(pending);
        assert!(!limited);
    }

    #[test]
    fn filesystem_pending_cap_applies_backpressure_instead_of_empty_replay() {
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        cache.worker.take();
        for index in 0..MAX_FILESYSTEM_CACHE_ENTRIES {
            cache.filesystem_pending.insert(FilesystemKey {
                request: FilesystemRequest {
                    request_id: format!("filesystem:occupied:{index}"),
                    kind: crate::rules::vm::FilesystemRequestKind::Test,
                    dialect: crate::rules::script::ScriptDialect::Bash,
                    path: format!("occupied-{index}"),
                    operator: Some("-e".into()),
                },
                working_directory: PathBuf::from("/tmp"),
            });
        }
        let request = FilesystemRequest {
            request_id: "filesystem:deferred".into(),
            kind: crate::rules::vm::FilesystemRequestKind::Test,
            dialect: crate::rules::script::ScriptDialect::Bash,
            path: "deferred".into(),
            operator: Some("-e".into()),
        };
        let (values, pending, limited) = cache.filesystem_values(&request, Path::new("/tmp"));
        assert!(values.is_none());
        assert!(pending);
        assert!(!limited);
    }

    #[test]
    fn pinned_filesystem_replays_fail_explicitly_instead_of_eviction_churn() {
        let mut cache = CompletionCache::new(256, 128);
        cache.worker.take();
        let working_directory = PathBuf::from("/snapshot");
        let old_request = FilesystemRequest {
            request_id: "filesystem:pinned".into(),
            kind: crate::rules::vm::FilesystemRequestKind::Read,
            dialect: crate::rules::script::ScriptDialect::Fish,
            path: "old".into(),
            operator: None,
        };
        let old_key = FilesystemKey {
            request: old_request,
            working_directory: working_directory.clone(),
        };
        cache.filesystem_entries.insert(
            old_key.clone(),
            FilesystemCacheEntry {
                values: vec!["pinned".into()],
                approximate_bytes: 256,
                last_used: 0,
                refreshed_at: Instant::now(),
            },
        );
        cache.filesystem_pins.insert(old_key);
        cache.used_bytes = 256;

        let request = FilesystemRequest {
            request_id: "filesystem:overflow".into(),
            kind: crate::rules::vm::FilesystemRequestKind::Read,
            dialect: crate::rules::script::ScriptDialect::Fish,
            path: "new".into(),
            operator: None,
        };
        let key = FilesystemKey {
            request: request.clone(),
            working_directory: working_directory.clone(),
        };
        let (request_tx, _request_rx) = mpsc::sync_channel(1);
        let (response_tx, response_rx) = mpsc::channel();
        cache.worker = Some(WorkerClient {
            requests: Some(request_tx),
            responses: response_rx,
            handle: None,
            stop: Arc::new(AtomicBool::new(false)),
            filesystem_generation: Arc::new(AtomicU64::new(cache.filesystem_generation)),
        });
        cache.filesystem_pending.insert(key.clone());
        response_tx
            .send(Response::Filesystem {
                key,
                values: vec!["new".into()],
                generation: cache.filesystem_generation,
                completed_at: Instant::now(),
            })
            .unwrap();
        cache.poll();
        let (values, pending, limited) = cache.filesystem_values(&request, &working_directory);
        assert!(values.is_none());
        assert!(!pending);
        assert!(limited);
        assert_eq!(cache.filesystem_entries.len(), 1);
    }

    #[test]
    fn completed_probe_values_are_replayed_from_cache() {
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let request = ProbeRequest {
            key: ProbeKey {
                executable: "printf".into(),
                arguments: vec!["alpha\\nbeta\\n".into()],
                environment: Vec::new(),
                working_directory: "/tmp".into(),
                parser: crate::rules::ir::ProbeParser::Lines,
                include_stderr: false,
            },
            probe_id: "script:test:0".into(),
            candidate_kind: crate::rules::ir::RuleCandidateKind::Value,
            append: crate::rules::ir::AppendPolicy::Space,
            timeout_ms: 1000,
            output_limit: 4096,
            cache_ttl_ms: 10_000,
            description: None,
            source: crate::rules::format::SourceKind::User,
            dynamic_authorized: true,
        };
        let (values, pending) = cache.probe_values(&request);
        assert!(values.is_none());
        assert!(pending);

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            cache.poll();
            let (values, pending) = cache.probe_values(&request);
            if let Some(values) = values {
                assert_eq!(values, ["alpha", "beta"]);
                assert!(!pending);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }

        let (values, pending) = cache.probe_values(&request);
        assert_eq!(values.unwrap(), ["alpha", "beta"]);
        assert!(!pending);

        cache.finish_dynamic_replay();
        let cache_key = ProbeCacheKey::from(&request);
        cache
            .probe_entries
            .get_mut(&cache_key)
            .unwrap()
            .refreshed_at = Instant::now() - Duration::from_secs(20);
        let (values, pending) = cache.probe_values(&request);
        assert!(
            values.is_none(),
            "expired probe values must not be replayed"
        );
        assert!(pending);
        cache.cancel_probes();

        let mut stricter = request.clone();
        stricter.output_limit = 1024;
        let (values, pending) = cache.probe_values(&stricter);
        assert!(values.is_none());
        assert!(pending);
    }

    #[test]
    fn probe_cancellation_is_out_of_band_and_acknowledged_before_unmasking() {
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let request = ProbeRequest {
            key: ProbeKey {
                executable: "sleep".into(),
                arguments: vec!["1".into()],
                environment: Vec::new(),
                working_directory: "/tmp".into(),
                parser: crate::rules::ir::ProbeParser::Lines,
                include_stderr: false,
            },
            probe_id: "script:test:cancel".into(),
            candidate_kind: crate::rules::ir::RuleCandidateKind::Value,
            append: crate::rules::ir::AppendPolicy::Space,
            timeout_ms: 1500,
            output_limit: 4096,
            cache_ttl_ms: 10_000,
            description: None,
            source: crate::rules::format::SourceKind::User,
            dynamic_authorized: true,
        };
        assert!(cache.probe_values(&request).1);
        assert!(cache.probe_signal_mask.is_some());
        cache.cancel_probes();
        assert!(cache.probe_cancel_pending.is_some());
        assert!(
            cache.probe_signal_mask.is_some(),
            "SIGCHLD must remain coordinated until worker cancellation is acknowledged"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while cache.probe_cancel_pending.is_some() {
            cache.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(cache.probe_signal_mask.is_none());
        assert!(cache.probe_entries.is_empty());
    }

    #[test]
    fn failed_probe_is_not_replayed_as_a_successful_empty_result() {
        let mut cache = CompletionCache::new(1024 * 1024, 128);
        let request = ProbeRequest {
            key: ProbeKey {
                executable: "false".into(),
                arguments: Vec::new(),
                environment: Vec::new(),
                working_directory: "/tmp".into(),
                parser: crate::rules::ir::ProbeParser::Lines,
                include_stderr: false,
            },
            probe_id: "script:test:failed".into(),
            candidate_kind: crate::rules::ir::RuleCandidateKind::Value,
            append: crate::rules::ir::AppendPolicy::Space,
            timeout_ms: 1000,
            output_limit: 4096,
            cache_ttl_ms: 10_000,
            description: None,
            source: crate::rules::format::SourceKind::User,
            dynamic_authorized: true,
        };
        assert!(cache.probe_values(&request).1);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            cache.poll();
            let (outcome, pending) = cache.probe_outcome(&request);
            if !pending {
                let outcome = outcome.expect("failed probes retain an explicit VM outcome");
                assert_eq!(outcome.status, 1);
                assert!(outcome.values.is_empty());
                assert!(cache.probe_values(&request).0.is_none());
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
    }
}
