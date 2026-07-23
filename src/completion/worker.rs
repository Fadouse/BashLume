use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::matcher::match_score;
use crate::rules::loader::{LoadedProgram, PackSummary, RuleStore};
use crate::rules::probe::ProbeSupervisor;
use crate::rules::vm::{ProbeKey, ProbeRequest};

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

#[derive(Debug)]
enum Request {
    Scan {
        key: ScanKey,
        max_candidates: usize,
        generation: u64,
    },
    LoadAccounts {
        home: Option<PathBuf>,
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
    RunProbe(ProbeRequest),
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
    Accounts {
        users: Vec<String>,
        hosts: Vec<String>,
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
    Probe {
        request: ProbeRequest,
        values: Vec<String>,
        error: Option<String>,
        completed_at: Instant,
    },
}

pub struct WorkerClient {
    requests: Sender<Request>,
    responses: Receiver<Response>,
    handle: Option<JoinHandle<()>>,
}

impl WorkerClient {
    pub fn start() -> std::io::Result<Self> {
        let (request_tx, request_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("bashlume-cache".into())
            .stack_size(256 * 1024)
            .spawn(move || worker_loop(request_rx, response_tx))?;
        Ok(Self {
            requests: request_tx,
            responses: response_rx,
            handle: Some(handle),
        })
    }

    fn send(&self, request: Request) -> bool {
        self.requests.send(request).is_ok()
    }

    fn try_receive(&self) -> Result<Response, TryRecvError> {
        self.responses.try_recv()
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.requests.send(Request::Stop);
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
struct CacheEntry {
    entries: Vec<DirectoryEntry>,
    truncated: bool,
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
    refreshed_at: Instant,
    ttl: Duration,
    approximate_bytes: usize,
    last_used: u64,
}

pub struct CompletionCache {
    worker: Option<WorkerClient>,
    entries: HashMap<ScanKey, CacheEntry>,
    pending: HashSet<ScanKey>,
    directory_generations: HashMap<PathBuf, u64>,
    path_directories: Vec<PathBuf>,
    users: Vec<String>,
    hosts: Vec<String>,
    byte_limit: usize,
    used_bytes: usize,
    clock: u64,
    max_candidates: usize,
    accounts_requested: bool,
    rule_generation: u64,
    rule_catalog_ready: bool,
    rule_summaries: Vec<PackSummary>,
    rule_entries: HashMap<String, RuleCacheEntry>,
    rule_pending: HashSet<String>,
    rule_errors: Vec<String>,
    rule_configuration: Option<(Vec<PathBuf>, Vec<PathBuf>)>,
    probe_entries: HashMap<ProbeKey, ProbeCacheEntry>,
    probe_pending: HashSet<ProbeKey>,
    probe_errors: Vec<String>,
}

impl CompletionCache {
    pub fn new(byte_limit: usize, max_candidates: usize) -> Self {
        Self {
            worker: WorkerClient::start().ok(),
            entries: HashMap::new(),
            pending: HashSet::new(),
            directory_generations: HashMap::new(),
            path_directories: Vec::new(),
            users: Vec::new(),
            hosts: Vec::new(),
            byte_limit,
            used_bytes: 0,
            clock: 0,
            max_candidates,
            accounts_requested: false,
            rule_generation: 0,
            rule_catalog_ready: true,
            rule_summaries: Vec::new(),
            rule_entries: HashMap::new(),
            rule_pending: HashSet::new(),
            rule_errors: Vec::new(),
            rule_configuration: None,
            probe_entries: HashMap::new(),
            probe_pending: HashSet::new(),
            probe_errors: Vec::new(),
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

    pub fn load_accounts(&mut self, home: Option<PathBuf>) {
        if self.accounts_requested {
            return;
        }
        if let Some(worker) = &self.worker {
            self.accounts_requested = worker.send(Request::LoadAccounts { home });
        }
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
            self.rule_catalog_ready = true;
        }
    }

    pub fn rule_programs(&mut self, command: &str) -> (Option<&[LoadedProgram]>, bool) {
        if command.is_empty() {
            return (None, false);
        }
        if !self.rule_entries.contains_key(command)
            && self.rule_catalog_ready
            && self.rule_pending.insert(command.to_owned())
        {
            let generation = self.rule_generation;
            let sent = self.worker.as_ref().is_some_and(|worker| {
                worker.send(Request::LoadRules {
                    command: command.to_owned(),
                    generation,
                })
            });
            if !sent {
                self.rule_pending.remove(command);
            }
        }
        let pending = !self.rule_catalog_ready || self.rule_pending.contains(command);
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

    pub fn probe_errors(&self) -> &[String] {
        &self.probe_errors
    }

    pub fn probe_values(&mut self, request: &ProbeRequest) -> (Option<&[String]>, bool) {
        let stale = self
            .probe_entries
            .get(&request.key)
            .is_none_or(|entry| entry.refreshed_at.elapsed() >= entry.ttl);
        if stale && self.probe_pending.insert(request.key.clone()) {
            let sent = self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.send(Request::RunProbe(request.clone())));
            if !sent {
                self.probe_pending.remove(&request.key);
            }
        }
        let pending = self.probe_pending.contains(&request.key);
        if let Some(entry) = self.probe_entries.get_mut(&request.key) {
            self.clock = self.clock.wrapping_add(1);
            entry.last_used = self.clock;
            (Some(&entry.values), pending)
        } else {
            (None, pending && self.worker.is_some())
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
        }

        let key = ScanKey {
            directory,
            prefix: String::new(),
            executable_only: false,
        };
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
        if !stale || !self.pending.insert(key.clone()) {
            return;
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
            self.pending.remove(&key);
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
                    self.rule_pending.clear();
                    self.probe_pending.clear();
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
                    let approximate_bytes = entries.iter().fold(0_usize, |total, entry| {
                        total
                            .saturating_add(std::mem::size_of::<DirectoryEntry>())
                            .saturating_add(entry.name.capacity())
                    });
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
                Response::Accounts { users, hosts } => {
                    self.users = users;
                    self.hosts = hosts;
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
                    let approximate_bytes = approximate_rule_bytes(&programs);
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
                Response::Probe {
                    request,
                    values,
                    error,
                    completed_at,
                } => {
                    self.probe_pending.remove(&request.key);
                    let failed = error.is_some();
                    if let Some(error) = error {
                        self.probe_errors
                            .push(format!("{}: {error}", request.probe_id));
                        if self.probe_errors.len() > 128 {
                            self.probe_errors.drain(..self.probe_errors.len() - 128);
                        }
                    }
                    let approximate_bytes = values.iter().fold(0_usize, |total, value| {
                        total
                            .saturating_add(std::mem::size_of::<String>())
                            .saturating_add(value.capacity())
                    });
                    self.clock = self.clock.wrapping_add(1);
                    if let Some(previous) = self.probe_entries.insert(
                        request.key,
                        ProbeCacheEntry {
                            values,
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

    pub fn for_each_command(&mut self, query: &str, mut visitor: impl FnMut(&str)) -> bool {
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
                    visitor(&entry.name);
                }
            } else {
                pending |= self.worker.is_some();
            }
        }
        pending
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

    pub fn hosts(&self) -> &[String] {
        &self.hosts
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
    }

    fn evict_to_limit(&mut self) {
        while self.used_bytes > self.byte_limit
            && self
                .entries
                .len()
                .saturating_add(self.rule_entries.len())
                .saturating_add(self.probe_entries.len())
                > 1
        {
            let oldest_directory = self
                .entries
                .iter()
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
            let minimum_clock = oldest_directory
                .as_ref()
                .map(|(_, clock)| *clock)
                .into_iter()
                .chain(oldest_rule.as_ref().map(|(_, clock)| *clock))
                .chain(oldest_probe.as_ref().map(|(_, clock)| *clock))
                .min();
            if oldest_probe
                .as_ref()
                .is_some_and(|(_, clock)| Some(*clock) == minimum_clock)
            {
                let key = oldest_probe.expect("oldest probe exists").0;
                if let Some(entry) = self.probe_entries.remove(&key) {
                    self.used_bytes = self.used_bytes.saturating_sub(entry.approximate_bytes);
                }
            } else if oldest_rule
                .as_ref()
                .is_some_and(|(_, clock)| Some(*clock) == minimum_clock)
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

fn worker_loop(requests: Receiver<Request>, responses: Sender<Response>) {
    let mut rules = RuleStore::default();
    let mut probes = ProbeSupervisor::default();
    loop {
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
        if let Some(request) = request {
            match request {
                Request::Scan {
                    key,
                    max_candidates,
                    generation,
                } => {
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
                Request::LoadAccounts { home } => {
                    let users = load_users();
                    let hosts = load_hosts(home.as_deref());
                    if responses.send(Response::Accounts { users, hosts }).is_err() {
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
                Request::RunProbe(request) => {
                    if !probes.submit(request.clone())
                        && responses
                            .send(Response::Probe {
                                request,
                                values: Vec::new(),
                                error: Some("probe queue rejected the request".into()),
                                completed_at: Instant::now(),
                            })
                            .is_err()
                    {
                        break;
                    }
                }
                Request::Stop => break,
            }
        }
        for outcome in probes.poll() {
            if responses
                .send(Response::Probe {
                    request: outcome.request,
                    values: outcome.values,
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
        total
            .saturating_add(std::mem::size_of_val(loaded))
            .saturating_add(metadata)
            .saturating_add(rules)
            .saturating_add(probes)
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

        let file_type = item.file_type().ok();
        let is_directory = file_type.as_ref().is_some_and(|kind| kind.is_dir());
        let executable = if is_directory {
            false
        } else {
            item.metadata()
                .ok()
                .is_some_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        };
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

fn load_users() -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            if let Some((name, _)) = line.split_once(':') {
                if !name.is_empty() {
                    users.push(name.to_owned());
                }
            }
        }
    }
    users.sort_unstable();
    users.dedup();
    users
}

fn load_hosts(home: Option<&Path>) -> Vec<String> {
    let mut hosts = HashSet::new();
    if let Ok(contents) = fs::read_to_string("/etc/hosts") {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or_default();
            for host in line.split_whitespace().skip(1) {
                hosts.insert(host.to_owned());
            }
        }
    }
    if let Some(home) = home {
        if let Ok(contents) = fs::read_to_string(home.join(".ssh/config")) {
            for line in contents.lines() {
                let mut words = line.split_whitespace();
                if words
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case("host"))
                {
                    for host in words {
                        if !host.contains(['*', '?', '!']) {
                            hosts.insert(host.to_owned());
                        }
                    }
                }
            }
        }
        if let Ok(contents) = fs::read_to_string(home.join(".ssh/known_hosts")) {
            for line in contents.lines() {
                let Some(field) = line.split_whitespace().next() else {
                    continue;
                };
                if field.starts_with('|') {
                    continue;
                }
                for host in field.split(',') {
                    let host = host
                        .trim_matches(['[', ']'])
                        .split(':')
                        .next()
                        .unwrap_or(host);
                    if !host.is_empty() {
                        hosts.insert(host.to_owned());
                    }
                }
            }
        }
    }
    let mut hosts: Vec<_> = hosts.into_iter().collect();
    hosts.sort_unstable();
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
}
