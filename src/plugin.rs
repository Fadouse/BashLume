use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::completion::context::CompletionContext;
use crate::completion::matcher::Candidate;
use crate::completion::{CompletionEngine, GhostSuggestion, longest_common_display_prefix};
use crate::config::{Config, DiagnosticsMode, HighlightMode};
use crate::ffi::{self, ReadlineCommand, RedisplayFunction};
use crate::render::{MenuView, RenderModel, Renderer};
use crate::shell::{KnownCommand, ShellSnapshot};
use crate::syntax::{CommandClass, SyntaxEngine};

static STATE: Mutex<Option<PluginState>> = Mutex::new(None);
static ORIGINAL_REDISPLAY: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_STARTUP: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_EVENT: AtomicUsize = AtomicUsize::new(0);
static EVENT_INPUT_TIMEOUT: AtomicI32 = AtomicI32::new(-1);
static MARK_ACTIVE_FUNCTION: AtomicUsize = AtomicUsize::new(0);
static FORKED_CHILD: AtomicBool = AtomicBool::new(false);
static ATFORK_REGISTERED: AtomicBool = AtomicBool::new(false);
static MODULE_PIN_HANDLE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    CompleteForward,
    CompleteBackward,
    AcceptAll,
    AcceptWord,
    EndOrAccept,
    Enter,
    OperateAndGetNext,
    PrefetchSpace,
    Cancel,
}

const REQUEST_FALLBACK: i32 = i32::MIN;

#[derive(Clone)]
struct SavedBinding {
    map: usize,
    sequence: Vec<u8>,
    original: Option<ReadlineCommand>,
    replacement: ReadlineCommand,
    action: Action,
}

struct MenuState {
    line: String,
    point: usize,
    candidates: Vec<Candidate>,
    selected: usize,
    pending: bool,
}

impl MenuState {
    fn matches_context(&self, line: &str, point: usize) -> bool {
        self.line == line && self.point == point
    }
}

struct PluginState {
    config: Config,
    enabled: bool,
    shell: ShellSnapshot,
    completion: CompletionEngine,
    syntax: SyntaxEngine,
    renderer: Renderer,
    bindings: Vec<SavedBinding>,
    menu: Option<MenuState>,
    last_ghost: Option<GhostSuggestion>,
    last_dynamic_context: Option<(String, usize)>,
    diagnostic_due: Option<Instant>,
}

impl PluginState {
    unsafe fn new() -> Result<Self, String> {
        let config = unsafe { Config::from_bash() };
        let mut shell = ShellSnapshot::default();
        unsafe { shell.refresh() };
        let mut completion = CompletionEngine::new(config.cache_limit_bytes, config.max_candidates);
        completion.configure_rules(
            config.rule_paths.clone(),
            config.trusted_rule_key_paths.clone(),
        );
        let syntax = SyntaxEngine::new().map_err(|error| error.to_string())?;
        Ok(Self {
            enabled: config.enabled,
            config,
            shell,
            completion,
            syntax,
            renderer: Renderer::default(),
            bindings: Vec::new(),
            menu: None,
            last_ghost: None,
            last_dynamic_context: None,
            diagnostic_due: None,
        })
    }

    unsafe fn refresh_prompt(&mut self) {
        self.completion.cancel_dynamic();
        unsafe { self.shell.refresh() };
        self.completion.refresh(&self.shell);
        self.menu = None;
        self.last_ghost = None;
        self.last_dynamic_context = None;
        self.diagnostic_due = None;
        unsafe { self.sync_event_hook() };
    }

    unsafe fn reload_config(&mut self) {
        self.config = unsafe { Config::from_bash() };
        self.enabled = self.config.enabled;
        self.completion
            .reconfigure(self.config.cache_limit_bytes, self.config.max_candidates);
        self.completion.configure_rules(
            self.config.rule_paths.clone(),
            self.config.trusted_rule_key_paths.clone(),
        );
        unsafe { self.sync_event_hook() };
    }

    fn refresh_menu(&mut self, line: &str, context: &CompletionContext) -> bool {
        let Some(current) = self.menu.as_ref() else {
            return false;
        };
        let previous = current
            .candidates
            .get(current.selected)
            .map(|candidate| candidate.value.clone());
        let result =
            self.completion
                .complete_explicit(context, &self.shell, self.config.max_candidates);
        let selected = previous
            .as_ref()
            .and_then(|value| {
                result
                    .candidates
                    .iter()
                    .position(|candidate| &candidate.value == value)
            })
            .unwrap_or(0);
        let changed = self.menu.as_ref().is_none_or(|menu| {
            !menu.matches_context(line, context.point)
                || menu.selected != selected
                || menu.pending != result.pending
                || menu.candidates != result.candidates
        });
        self.menu = Some(MenuState {
            line: line.to_owned(),
            point: context.point,
            candidates: result.candidates,
            selected,
            pending: result.pending,
        });
        changed
    }

    unsafe fn poll_pending_menu(&mut self) -> bool {
        if !self.menu.as_ref().is_some_and(|menu| menu.pending) {
            return false;
        }
        let Some((line, point)) = (unsafe { readline_line() }) else {
            return false;
        };
        let context = CompletionContext::analyze(&line, point);
        self.refresh_menu(&line, &context)
    }

    unsafe fn sync_event_hook(&self) {
        let completion_pending = self.completion.background_pending()
            || self.enabled && self.menu.as_ref().is_some_and(|menu| menu.pending);
        let diagnostic_pending = self.enabled && self.diagnostic_due.is_some();
        unsafe {
            configure_event_hook(completion_pending || diagnostic_pending, completion_pending)
        };
    }

    unsafe fn render(&mut self) {
        if !self.enabled {
            return;
        }
        let Some((line, point)) = (unsafe { readline_line() }) else {
            return;
        };
        let context = CompletionContext::analyze(&line, point);
        self.completion.prefetch_rules(&context);
        let dynamic_context = (line.clone(), point);
        if self.last_dynamic_context.as_ref() != Some(&dynamic_context) {
            self.completion.cancel_dynamic();
            self.last_dynamic_context = Some(dynamic_context);
        }
        let vi_command_mode = unsafe { in_vi_command_mode() };
        if vi_command_mode {
            self.menu = None;
            self.last_ghost = None;
        }

        let refresh_menu = self
            .menu
            .as_ref()
            .is_some_and(|menu| !menu.matches_context(&line, point) || menu.pending);
        if refresh_menu {
            self.refresh_menu(&line, &context);
        }

        if !vi_command_mode {
            self.last_ghost = self
                .menu
                .as_ref()
                .and_then(|menu| menu.candidates.get(menu.selected))
                .and_then(|candidate| ghost_for_candidate(&context, candidate))
                .or_else(|| unsafe {
                    self.completion
                        .ghost(&context, &self.shell, self.config.max_candidates)
                });
        }

        let shell = &self.shell;
        let completion = &self.completion;
        let highlighted = self.syntax.highlight(&line, |command| {
            if command.contains('/') {
                return CommandClass::Pending;
            }
            match shell.known_shell_command(command) {
                Some(KnownCommand::Alias | KnownCommand::Function | KnownCommand::Builtin) => {
                    CommandClass::Builtin
                }
                None => match completion.command_known(command) {
                    Some(true) => CommandClass::Valid,
                    Some(false) => CommandClass::Unknown,
                    None => CommandClass::Pending,
                },
            }
        });

        let has_syntax_error = highlighted.diagnostic.is_some();
        if has_syntax_error {
            self.last_ghost = None;
        }
        let diagnostic = match (self.config.diagnostics, highlighted.diagnostic.as_ref()) {
            (DiagnosticsMode::Inline, Some(diagnostic)) => {
                let due = highlighted
                    .changed_at
                    .checked_add(Duration::from_millis(self.config.diagnostic_delay_ms))
                    .unwrap_or_else(Instant::now);
                if Instant::now() >= due {
                    self.diagnostic_due = None;
                    Some(diagnostic)
                } else {
                    self.diagnostic_due = Some(due);
                    None
                }
            }
            _ => {
                self.diagnostic_due = None;
                None
            }
        };
        let menu = self.menu.as_ref().map(|menu| MenuView {
            candidates: &menu.candidates,
            selected: menu.selected.min(menu.candidates.len().saturating_sub(1)),
        });
        let model = RenderModel {
            line: &line,
            point,
            styles: &highlighted.styles,
            ghost: self.last_ghost.as_ref().map(|ghost| ghost.suffix.as_str()),
            error_marker: has_syntax_error
                && self.config.diagnostics == DiagnosticsMode::Marker
                && self.config.highlight != HighlightMode::Off,
            menu,
            diagnostic,
        };
        unsafe { self.renderer.draw(model, &self.config) };
        unsafe { self.sync_event_hook() };
    }

    unsafe fn complete(&mut self, backwards: bool) -> i32 {
        if !self.enabled {
            return REQUEST_FALLBACK;
        }

        let stale_menu = self.menu.as_ref().is_some_and(|menu| {
            unsafe { readline_line() }
                .is_none_or(|(line, point)| !menu.matches_context(&line, point))
        });
        if stale_menu {
            self.completion.cancel_dynamic();
            self.menu = None;
        }

        if self
            .menu
            .as_ref()
            .is_some_and(|menu| menu.candidates.is_empty())
        {
            // Retry empty results instead of leaving either a pending or a
            // completed empty placeholder menu sticky forever.
            self.menu = None;
        } else if let Some(menu) = &mut self.menu {
            if !menu.candidates.is_empty() {
                if backwards {
                    menu.selected = menu
                        .selected
                        .checked_sub(1)
                        .unwrap_or(menu.candidates.len() - 1);
                } else {
                    menu.selected = (menu.selected + 1) % menu.candidates.len();
                }
            }
            return 0;
        }

        let Some((line, point)) = (unsafe { readline_line() }) else {
            return REQUEST_FALLBACK;
        };
        let dynamic_context = (line.clone(), point);
        if self.last_dynamic_context.as_ref() != Some(&dynamic_context) {
            self.completion.cancel_dynamic();
            self.last_dynamic_context = Some(dynamic_context);
        }
        let mut context = CompletionContext::analyze(&line, point);
        let mut result =
            self.completion
                .complete_explicit(&context, &self.shell, self.config.max_candidates);
        if result.candidates.is_empty() {
            if !result.pending {
                unsafe { ffi::rl_ding() };
            }
            self.menu = Some(MenuState {
                line,
                point,
                candidates: result.candidates,
                selected: 0,
                pending: result.pending,
            });
            return 0;
        }

        if result.pending {
            // A result is not unique until every relevant asynchronous scan
            // has completed. Committing it now can append a space before a
            // longer prefix candidate arrives from another PATH directory.
            self.menu = Some(MenuState {
                line,
                point,
                candidates: result.candidates,
                selected: 0,
                pending: true,
            });
            return 0;
        }

        if result.candidates.len() == 1 {
            let candidate = result.candidates.remove(0);
            unsafe { apply_candidate(&context, &candidate) };
            self.menu = None;
            return 0;
        }

        if let Some(common) = longest_common_display_prefix(&result.candidates) {
            let query = completion_match_query(&context);
            if common.len() > query.len() && common.starts_with(query) {
                let mut partial = result.candidates[0].clone();
                if let Some(base) = partial.value.strip_suffix(&partial.display) {
                    partial.value = format!("{base}{common}");
                    partial.display = common;
                    partial.append_space = false;
                    unsafe { apply_candidate(&context, &partial) };
                    if let Some((new_line, new_point)) = unsafe { readline_line() } {
                        let dynamic_context = (new_line.clone(), new_point);
                        if self.last_dynamic_context.as_ref() != Some(&dynamic_context) {
                            self.completion.cancel_dynamic();
                            self.last_dynamic_context = Some(dynamic_context);
                        }
                        context = CompletionContext::analyze(&new_line, new_point);
                        result = self.completion.complete_explicit(
                            &context,
                            &self.shell,
                            self.config.max_candidates,
                        );
                    }
                }
            }
        }

        let (current_line, current_point) = unsafe { readline_line() }.unwrap_or((line, point));
        self.menu = Some(MenuState {
            line: current_line,
            point: current_point,
            candidates: result.candidates,
            selected: 0,
            pending: result.pending,
        });
        0
    }

    unsafe fn accept_all(&mut self, fallback: Action, count: i32, key: i32) -> i32 {
        if self.enabled {
            if let Some(ghost) = self.last_ghost.take() {
                if !ghost.suffix.is_empty() {
                    if let Ok(text) = CString::new(ghost.suffix) {
                        unsafe { ffi::rl_insert_text(text.as_ptr()) };
                        self.menu = None;
                        return 0;
                    }
                }
            }
        }
        let _ = (fallback, count, key);
        REQUEST_FALLBACK
    }

    unsafe fn accept_word(&mut self, count: i32, key: i32) -> i32 {
        if self.enabled {
            if let Some(ghost) = &mut self.last_ghost {
                let length = next_shell_word_length(&ghost.suffix);
                if length > 0 {
                    let accepted = ghost.suffix[..length].to_owned();
                    if let Ok(text) = CString::new(accepted.as_str()) {
                        unsafe { ffi::rl_insert_text(text.as_ptr()) };
                        ghost.suffix.drain(..length);
                        self.menu = None;
                        return 0;
                    }
                }
            }
        }
        let _ = (count, key);
        REQUEST_FALLBACK
    }

    unsafe fn enter(&mut self, count: i32, key: i32) -> i32 {
        if self.enabled {
            if let Some(menu) = self.menu.take() {
                if let Some(candidate) = menu.candidates.get(menu.selected) {
                    if let Some((line, point)) = unsafe { readline_line() } {
                        if menu.matches_context(&line, point) {
                            let context = CompletionContext::analyze(&line, point);
                            unsafe { apply_candidate(&context, candidate) };
                            self.last_ghost = None;
                            return 0;
                        }
                    }
                }
            }
        }
        unsafe { self.accept_command(Action::Enter, count, key) }
    }

    unsafe fn accept_command(&mut self, fallback: Action, count: i32, key: i32) -> i32 {
        if self.enabled {
            self.menu = None;
            if let Some((line, point)) = unsafe { readline_line() } {
                unsafe { self.renderer.clear_extras(&line, point) };
            }
            self.last_ghost = None;
            self.completion.quiesce_dynamic_before_command();
            unsafe { self.sync_event_hook() };
        }
        let _ = (fallback, count, key);
        REQUEST_FALLBACK
    }

    unsafe fn cancel(&mut self, count: i32, key: i32) -> i32 {
        if self.menu.take().is_some() {
            self.completion.cancel_dynamic();
            self.last_ghost = None;
            unsafe { self.sync_event_hook() };
            return 0;
        }
        // Readline's native `abort` longjmps to its C recovery point and must
        // never be called through a Rust frame. The default Ctrl-G binding is
        // therefore left untouched; an explicitly invoked BashLume defun uses
        // the safe public subset of abort's behavior.
        let _ = (count, key);
        unsafe {
            ffi::rl_ding();
            ffi::rl_clear_pending_input();
        }
        0
    }

    unsafe fn fallback_function(&self, action: Action, key: i32) -> Option<ReadlineCommand> {
        // `rl_executing_keymap` is the nested map for the final byte of an
        // escape sequence. Saved bindings use the active top-level editing
        // map, while `rl_executing_keyseq` identifies the exact sequence.
        let map = unsafe { ffi::rl_get_keymap() } as usize;
        let executing_sequence = unsafe { ffi::rl_executing_keyseq };
        let sequence = (!executing_sequence.is_null())
            .then(|| unsafe { CStr::from_ptr(executing_sequence) }.to_bytes());
        if let Some(binding) = sequence
            .and_then(|sequence| {
                self.bindings.iter().find(|binding| {
                    binding.action == action && binding.map == map && binding.sequence == sequence
                })
            })
            .or_else(|| {
                self.bindings.iter().find(|binding| {
                    binding.action == action
                        && binding.map == map
                        && binding.sequence.len() == 1
                        && i32::from(binding.sequence[0]) == key
                })
            })
            .or_else(|| {
                self.bindings
                    .iter()
                    .find(|binding| binding.action == action && binding.map == map)
            })
        {
            if binding.original.is_none_or(|original| {
                !is_bashlume_wrapper(original) && !is_readline_abort(original)
            }) {
                return binding.original;
            }
        }
        named_fallback(action)
    }
}

fn is_readline_abort(function: ReadlineCommand) -> bool {
    unsafe { ffi::rl_named_function(c"abort".as_ptr()) }
        .is_some_and(|abort| abort as usize == function as usize)
}

fn is_bashlume_wrapper(function: ReadlineCommand) -> bool {
    if [
        complete_forward as ReadlineCommand,
        complete_backward,
        accept_all,
        end_or_accept,
        accept_word,
        enter,
        operate_and_get_next,
        insert_space_and_prefetch,
        cancel,
    ]
    .into_iter()
    .any(|wrapper| wrapper as usize == function as usize)
    {
        return true;
    }
    // NODELETE permits a later BashLume build to coexist with retained defuns
    // from an older DSO. Reject wrappers from any BashLume module, not only
    // function addresses from this build.
    let mut information = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    if unsafe {
        libc::dladdr(
            function as *const () as *const libc::c_void,
            information.as_mut_ptr(),
        )
    } == 0
    {
        return false;
    }
    let information = unsafe { information.assume_init() };
    if information.dli_fname.is_null() {
        return false;
    }
    unsafe { CStr::from_ptr(information.dli_fname) }
        .to_bytes()
        .windows(b"bashlume".len())
        .any(|window| window.eq_ignore_ascii_case(b"bashlume"))
}

unsafe fn pin_shared_object() -> Result<(), String> {
    if MODULE_PIN_HANDLE.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let mut information = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
    if unsafe {
        libc::dladdr(
            load as *const () as *const libc::c_void,
            information.as_mut_ptr(),
        )
    } == 0
    {
        return Err("could not identify the BashLume shared object".into());
    }
    let information = unsafe { information.assume_init() };
    if information.dli_fname.is_null() {
        return Err("BashLume shared object has no loader path".into());
    }
    let handle = unsafe {
        libc::dlopen(
            information.dli_fname,
            libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_NODELETE,
        )
    };
    if handle.is_null() {
        let detail = unsafe {
            let error = libc::dlerror();
            (!error.is_null()).then(|| CStr::from_ptr(error).to_string_lossy().into_owned())
        }
        .unwrap_or_else(|| "unknown dynamic-loader error".into());
        return Err(format!(
            "could not pin the BashLume shared object: {detail}"
        ));
    }
    // Deliberately retain this reference for process lifetime. Readline defun
    // entries and pthread_atfork handlers cannot be unregistered safely.
    MODULE_PIN_HANDLE.store(handle as usize, Ordering::Release);
    Ok(())
}

fn named_fallback(action: Action) -> Option<ReadlineCommand> {
    let name = match action {
        Action::CompleteForward | Action::CompleteBackward => c"complete",
        Action::AcceptAll => c"forward-char",
        Action::AcceptWord => c"forward-word",
        Action::EndOrAccept => c"end-of-line",
        Action::Enter => c"accept-line",
        Action::OperateAndGetNext => c"operate-and-get-next",
        Action::PrefetchSpace => c"self-insert",
        // Native abort performs a longjmp and cannot be called through Rust.
        Action::Cancel => return None,
    };
    unsafe { ffi::rl_named_function(name.as_ptr()) }
}

pub unsafe fn load() -> Result<(), String> {
    if unsafe { ffi::interactive_shell } == 0 {
        return Err("not an interactive Bash shell".into());
    }
    if unsafe { ffi::isatty(libc::STDERR_FILENO) } == 0 {
        return Err("Readline output is not attached to a terminal".into());
    }
    unsafe { pin_shared_object()? };

    let mut guard = lock_state();
    if guard.is_some() {
        return Ok(());
    }
    let mut state = unsafe { PluginState::new()? };

    let original_redisplay = unsafe { ffi::rl_redisplay_function }.unwrap_or(ffi::rl_redisplay);
    if original_redisplay as usize == redisplay_callback as *const () as usize {
        return Err("redisplay hook is already installed".into());
    }
    ORIGINAL_REDISPLAY.store(original_redisplay as usize, Ordering::Release);
    let original_startup = unsafe { ffi::rl_startup_hook };
    ORIGINAL_STARTUP.store(
        original_startup.map_or(0, |function| function as usize),
        Ordering::Release,
    );
    let original_event = unsafe { ffi::rl_event_hook };
    ORIGINAL_EVENT.store(
        original_event.map_or(0, |function| function as usize),
        Ordering::Release,
    );
    if !ATFORK_REGISTERED.load(Ordering::Acquire) {
        let atfork_status = unsafe { libc::pthread_atfork(None, None, Some(mark_forked_child)) };
        if atfork_status != 0 {
            return Err(format!(
                "could not register fork-safety handler: {}",
                std::io::Error::from_raw_os_error(atfork_status)
            ));
        }
        ATFORK_REGISTERED.store(true, Ordering::Release);
    }

    unsafe { install_bindings(&mut state) };
    unsafe {
        ffi::rl_redisplay_function = Some(redisplay_callback);
        ffi::rl_startup_hook = Some(startup_callback);
        configure_event_hook(false, false);
    }
    let mark_active = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"rl_mark_active_p".as_ptr()) };
    MARK_ACTIVE_FUNCTION.store(mark_active as usize, Ordering::Release);
    FORKED_CHILD.store(false, Ordering::Release);
    *guard = Some(state);
    Ok(())
}

pub unsafe fn unload() {
    let mut guard = lock_state();
    let Some(mut state) = guard.take() else {
        return;
    };
    let forked_child = FORKED_CHILD.load(Ordering::Acquire);
    if !forked_child {
        state.completion.stop();
    }
    unsafe { restore_bindings(&state.bindings) };

    let original = original_redisplay();
    if unsafe { ffi::rl_redisplay_function }
        .is_some_and(|function| function as usize == redisplay_callback as *const () as usize)
    {
        unsafe { ffi::rl_redisplay_function = Some(original) };
    }
    if unsafe { ffi::rl_startup_hook }
        .is_some_and(|function| function as usize == startup_callback as *const () as usize)
    {
        unsafe { ffi::rl_startup_hook = original_startup() };
    }
    if unsafe { ffi::rl_event_hook }
        .is_some_and(|function| function as usize == event_callback as *const () as usize)
    {
        unsafe { configure_event_hook(false, false) };
    } else {
        unsafe { restore_event_input_timeout() };
    }
    if forked_child {
        // The worker thread does not survive fork. Leaking its inherited
        // channel handles is safer than running a thread destructor that can
        // never join; the short-lived child reclaims them at exit/exec.
        std::mem::forget(state);
    }
}

pub unsafe fn control(arguments: *mut ffi::WordList) -> i32 {
    let arguments = unsafe { collect_arguments(arguments) };
    let command = arguments.first().map(String::as_str).unwrap_or("status");
    let mut guard = lock_state();
    let Some(state) = guard.as_mut() else {
        eprintln!("bashlume: plugin state is not loaded");
        return 1;
    };
    match command {
        "status" => {
            println!(
                "bashlume: {} (version: {}; providers: {}; rules: {} packs/{} loaded blocks; cache: {} entries, {} KiB)",
                if state.enabled { "enabled" } else { "disabled" },
                env!("CARGO_PKG_VERSION"),
                state.completion.provider_names(),
                state.completion.rule_pack_count(),
                state.completion.rule_cache_entries(),
                state.completion.cache_entries(),
                state.completion.cache_bytes() / 1024,
            );
            0
        }
        "enable" => {
            state.enabled = true;
            0
        }
        "disable" => {
            // `disable` can be reached reentrantly from a bind -x callback.
            // Finish probe cancellation before native accept-line paths become
            // eligible, so no command can inherit BashLume's SIGCHLD mask.
            state.completion.quiesce_dynamic_before_command();
            state.enabled = false;
            state.menu = None;
            state.last_ghost = None;
            unsafe { state.sync_event_hook() };
            0
        }
        "reload" => {
            unsafe { state.reload_config() };
            0
        }
        "stats" => {
            state.completion.poll_background();
            println!(
                "cache_bytes={} cache_entries={} rule_blocks={} max_candidates={}",
                state.completion.cache_bytes(),
                state.completion.cache_entries(),
                state.completion.rule_cache_entries(),
                state.config.max_candidates,
            );
            0
        }
        "rules" => {
            state.completion.poll_background();
            println!("{}", state.completion.rules_report());
            0
        }
        "help" | "--help" | "-h" => {
            println!("usage: bashlume [status|enable|disable|reload|stats|rules|help]");
            0
        }
        _ => {
            eprintln!("bashlume: unknown subcommand: {command}");
            2
        }
    }
}

unsafe extern "C" fn redisplay_callback() {
    call_original_redisplay();
    if FORKED_CHILD.load(Ordering::Acquire) {
        return;
    }
    let result = std::panic::catch_unwind(|| {
        let searching = unsafe { ffi::rl_readline_state }
            & (ffi::RL_STATE_ISEARCH
                | ffi::RL_STATE_NSEARCH
                | ffi::RL_STATE_SEARCH
                | ffi::RL_STATE_MACRODEF
                | ffi::RL_STATE_COMPLETING
                | ffi::RL_STATE_SIGHANDLER)
            != 0;
        if searching || mark_active() {
            write_clear_to_end();
            return;
        }
        if let Some(state) = lock_state().as_mut() {
            // Native Readline abort resets `rl_last_func` before its C
            // longjmp. Ctrl-G remains natively bound, so clear any BashLume
            // menu on the subsequent redisplay without invoking abort here.
            if state.menu.is_some() && unsafe { ffi::rl_last_func }.is_none() {
                state.menu = None;
                state.completion.cancel_dynamic();
                state.last_ghost = None;
                unsafe { state.sync_event_hook() };
            }
            unsafe { state.render() };
        }
    });
    if result.is_err() {
        if let Some(state) = lock_state().as_mut() {
            state.enabled = false;
        }
        eprintln!("bashlume: redisplay failed; falling back to native Readline");
    }
}

unsafe extern "C" fn startup_callback() -> i32 {
    let status = original_startup().map_or(0, |function| unsafe { function() });
    if !FORKED_CHILD.load(Ordering::Acquire) {
        let _ = std::panic::catch_unwind(|| {
            if let Some(state) = lock_state().as_mut() {
                unsafe { state.refresh_prompt() };
            }
        });
    }
    status
}

unsafe extern "C" fn event_callback() -> i32 {
    let status = original_event().map_or(0, |function| unsafe { function() });
    if FORKED_CHILD.load(Ordering::Acquire) {
        unsafe { configure_event_hook(false, false) };
        return status;
    }
    let busy = unsafe { ffi::rl_readline_state }
        & (ffi::RL_STATE_ISEARCH
            | ffi::RL_STATE_NSEARCH
            | ffi::RL_STATE_SEARCH
            | ffi::RL_STATE_MACRODEF
            | ffi::RL_STATE_COMPLETING
            | ffi::RL_STATE_SIGHANDLER)
        != 0;
    if busy || mark_active() {
        return status;
    }

    let should_redraw = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        let Some(state) = guard.as_mut() else {
            return false;
        };
        let background_changed = state.completion.poll_background();
        let changed = if state.enabled {
            let menu_changed = unsafe { state.poll_pending_menu() };
            let background_changed = background_changed && state.menu.is_none();
            let diagnostic_due = state
                .diagnostic_due
                .is_some_and(|deadline| Instant::now() >= deadline);
            background_changed || menu_changed || diagnostic_due
        } else {
            false
        };
        unsafe { state.sync_event_hook() };
        changed
    })) {
        Ok(changed) => changed,
        Err(_) => {
            if let Some(state) = lock_state().as_mut() {
                state.enabled = false;
            }
            unsafe { configure_event_hook(false, false) };
            eprintln!("bashlume: asynchronous redraw failed; falling back to native Readline");
            false
        }
    };
    if should_redraw {
        unsafe { ffi::rl_forced_update_display() };
    }
    status
}

unsafe extern "C" fn complete_forward(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.complete(false) },
        count,
        key,
        Action::CompleteForward,
    )
}

unsafe extern "C" fn complete_backward(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.complete(true) },
        count,
        key,
        Action::CompleteBackward,
    )
}

unsafe extern "C" fn accept_all(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.accept_all(Action::AcceptAll, count, key) },
        count,
        key,
        Action::AcceptAll,
    )
}

unsafe extern "C" fn end_or_accept(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.accept_all(Action::EndOrAccept, count, key) },
        count,
        key,
        Action::EndOrAccept,
    )
}

unsafe extern "C" fn accept_word(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.accept_word(count, key) },
        count,
        key,
        Action::AcceptWord,
    )
}

unsafe extern "C" fn enter(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.enter(count, key) },
        count,
        key,
        Action::Enter,
    )
}

unsafe extern "C" fn operate_and_get_next(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.accept_command(Action::OperateAndGetNext, count, key) },
        count,
        key,
        Action::OperateAndGetNext,
    )
}

unsafe extern "C" fn insert_space_and_prefetch(count: i32, key: i32) -> i32 {
    callback_or(0, |_| REQUEST_FALLBACK, count, key, Action::PrefetchSpace)
}

unsafe extern "C" fn cancel(count: i32, key: i32) -> i32 {
    callback_or(
        0,
        |state| unsafe { state.cancel(count, key) },
        count,
        key,
        Action::Cancel,
    )
}

fn callback_or(
    default: i32,
    callback: impl FnOnce(&mut PluginState) -> i32,
    count: i32,
    key: i32,
    fallback: Action,
) -> i32 {
    enum Prepared {
        Return(i32),
        Fallback(Option<ReadlineCommand>),
    }

    let forked_child = FORKED_CHILD.load(Ordering::Acquire);
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        let Some(state) = guard.as_mut() else {
            return Prepared::Fallback(named_fallback(fallback));
        };
        let result = if forked_child || !state.enabled {
            REQUEST_FALLBACK
        } else {
            callback(state)
        };
        if result == REQUEST_FALLBACK {
            Prepared::Fallback(unsafe { state.fallback_function(fallback, key) })
        } else {
            Prepared::Return(result)
        }
    }))
    .unwrap_or(Prepared::Return(default));

    match prepared {
        Prepared::Return(status) => status,
        Prepared::Fallback(function) => {
            // Readline commands may re-enter BashLume or longjmp (notably
            // `abort`), so no Rust mutex guard may be live across this call.
            let status = function.map_or(default, |function| unsafe { function(count, key) });
            if function.is_some() && fallback == Action::PrefetchSpace && !forked_child {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut guard = lock_state();
                    let Some(state) = guard.as_mut().filter(|state| state.enabled) else {
                        return;
                    };
                    if let Some((line, point)) = unsafe { readline_line() } {
                        let context = CompletionContext::analyze(&line, point);
                        state.completion.prefetch_rules(&context);
                        unsafe { state.sync_event_hook() };
                    }
                }));
            }
            status
        }
    }
}

unsafe fn install_binding(
    state: &mut PluginState,
    map: ffi::Keymap,
    sequence: &[u8],
    replacement: ReadlineCommand,
    action: Action,
) {
    if map.is_null() {
        return;
    }
    let Ok(sequence_c) = CString::new(sequence) else {
        return;
    };
    // Installing a longer sequence can replace a function or macro on one of
    // its proper prefixes with a nested keymap. That topology cannot be
    // restored by rebinding only the leaf, so intercept only sequences whose
    // complete prefix chain is already composed of keymaps.
    for prefix_length in 1..sequence.len() {
        let mut prefix_kind = ffi::ISFUNC;
        unsafe {
            ffi::rl_function_of_keyseq_len(
                sequence.as_ptr().cast(),
                prefix_length,
                map,
                &mut prefix_kind,
            )
        };
        if prefix_kind != ffi::ISKMAP {
            return;
        }
    }
    let mut kind = ffi::ISFUNC;
    let original = unsafe {
        ffi::rl_function_of_keyseq_len(sequence.as_ptr().cast(), sequence.len(), map, &mut kind)
    };
    // Readline does not expose a symmetric API for recovering the payload of
    // macros and keymap bindings. Preserve such custom bindings rather than
    // replacing them with a callback that cannot restore or invoke them.
    if kind != ffi::ISFUNC {
        return;
    }
    if unsafe { ffi::rl_bind_keyseq_in_map(sequence_c.as_ptr(), Some(replacement), map) } == 0 {
        state.bindings.push(SavedBinding {
            map: map as usize,
            sequence: sequence.to_vec(),
            original,
            replacement,
            action,
        });
    }
}

unsafe fn install_space_prefetch_binding(state: &mut PluginState, map: ffi::Keymap) {
    if map.is_null() {
        return;
    }
    let mut kind = ffi::ISFUNC;
    let original =
        unsafe { ffi::rl_function_of_keyseq_len(b" ".as_ptr().cast(), 1, map, &mut kind) };
    let self_insert = unsafe { ffi::rl_named_function(c"self-insert".as_ptr()) };
    if kind != ffi::ISFUNC
        || original.map(|function| function as usize)
            != self_insert.map(|function| function as usize)
    {
        return;
    }
    unsafe {
        install_binding(
            state,
            map,
            b" ",
            insert_space_and_prefetch,
            Action::PrefetchSpace,
        )
    };
}

unsafe fn install_bindings(state: &mut PluginState) {
    let definitions: &[(&CStr, ReadlineCommand)] = &[
        (c"bashlume-complete", complete_forward),
        (c"bashlume-complete-backward", complete_backward),
        (c"bashlume-accept", accept_all),
        (c"bashlume-accept-word", accept_word),
        (c"bashlume-end-or-accept", end_or_accept),
        (c"bashlume-enter", enter),
        (c"bashlume-operate-and-get-next", operate_and_get_next),
        (c"bashlume-prefetch-space", insert_space_and_prefetch),
        (c"bashlume-cancel", cancel),
    ];
    for (name, function) in definitions {
        unsafe { ffi::rl_add_defun(name.as_ptr(), Some(*function), -1) };
    }

    let editing_bindings: &[(&[u8], ReadlineCommand, Action)] = &[
        (b"\t", complete_forward, Action::CompleteForward),
        (b"\x1b[Z", complete_backward, Action::CompleteBackward),
        (b"\x1b[C", accept_all, Action::AcceptAll),
        (b"\x1bOC", accept_all, Action::AcceptAll),
        (b"\x1b[F", end_or_accept, Action::EndOrAccept),
        (b"\x1bOF", end_or_accept, Action::EndOrAccept),
        (b"\x1b[1;3C", accept_word, Action::AcceptWord),
        (b"\x1b\x1b[C", accept_word, Action::AcceptWord),
        (b"\r", enter, Action::Enter),
        (b"\n", enter, Action::Enter),
    ];
    for map_name in [c"emacs-standard", c"vi-insert"] {
        let map = unsafe { ffi::rl_get_keymap_by_name(map_name.as_ptr()) };
        for &(sequence, replacement, action) in editing_bindings {
            unsafe { install_binding(state, map, sequence, replacement, action) };
        }
        unsafe { install_space_prefetch_binding(state, map) };
    }

    let vi_movement = unsafe { ffi::rl_get_keymap_by_name(c"vi-move".as_ptr()) };
    for sequence in [b"\r".as_slice(), b"\n".as_slice()] {
        unsafe { install_binding(state, vi_movement, sequence, enter, Action::Enter) };
    }

    let emacs = unsafe { ffi::rl_get_keymap_by_name(c"emacs-standard".as_ptr()) };
    unsafe {
        install_binding(
            state,
            emacs,
            b"\x0f",
            operate_and_get_next,
            Action::OperateAndGetNext,
        )
    };
}

unsafe fn restore_bindings(bindings: &[SavedBinding]) {
    for binding in bindings {
        let map = binding.map as ffi::Keymap;
        let current = unsafe {
            ffi::rl_function_of_keyseq_len(
                binding.sequence.as_ptr().cast(),
                binding.sequence.len(),
                map,
                std::ptr::null_mut(),
            )
        };
        if current.is_none_or(|function| function as usize != binding.replacement as usize) {
            continue;
        }
        if let Ok(sequence) = CString::new(binding.sequence.as_slice()) {
            unsafe { ffi::rl_bind_keyseq_in_map(sequence.as_ptr(), binding.original, map) };
        }
    }
}

unsafe fn apply_candidate(context: &CompletionContext, candidate: &Candidate) {
    let replacement = context.replacement_for(candidate);
    let Ok(replacement) = CString::new(replacement) else {
        return;
    };
    unsafe {
        ffi::rl_begin_undo_group();
        ffi::rl_point = context.replace_end as i32;
        ffi::rl_delete_text(context.replace_start as i32, context.replace_end as i32);
        ffi::rl_point = context.replace_start as i32;
        ffi::rl_insert_text(replacement.as_ptr());
        ffi::rl_end_undo_group();
    }
}

fn ghost_for_candidate(
    context: &CompletionContext,
    candidate: &Candidate,
) -> Option<GhostSuggestion> {
    if context.point != context.line.len() || !candidate.is_strong_prefix() {
        return None;
    }
    let (line, _) = context.apply(candidate);
    if line.len() <= context.line.len() || !line.starts_with(&context.line) {
        return None;
    }
    let suffix = line[context.line.len()..].to_owned();
    (!suffix.trim().is_empty()).then_some(GhostSuggestion { suffix })
}

fn completion_match_query(context: &CompletionContext) -> &str {
    if context.query.starts_with('$') || context.query.starts_with('~') {
        &context.query
    } else {
        context.query.rsplit('/').next().unwrap_or(&context.query)
    }
}

fn next_shell_word_length(suffix: &str) -> usize {
    let mut end = 0_usize;
    let mut saw_word = false;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in suffix.char_indices() {
        if escaped {
            escaped = false;
            saw_word = true;
            end = index + character.len_utf8();
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            end = index + 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            saw_word = true;
            end = index + 1;
            continue;
        }
        let separator =
            quote.is_none() && (character.is_whitespace() || ";|&()<>".contains(character));
        if separator && saw_word {
            break;
        }
        if !separator {
            saw_word = true;
        }
        end = index + character.len_utf8();
    }
    end
}

unsafe fn in_vi_command_mode() -> bool {
    let movement = unsafe { ffi::rl_get_keymap_by_name(c"vi-move".as_ptr()) };
    !movement.is_null() && unsafe { ffi::rl_get_keymap() } == movement
}

unsafe fn readline_line() -> Option<(String, usize)> {
    let pointer = unsafe { ffi::rl_line_buffer };
    let end = unsafe { ffi::rl_end.max(0) as usize };
    if pointer.is_null() {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), end) };
    let line = std::str::from_utf8(bytes).ok()?.to_owned();
    let point = unsafe { ffi::rl_point.max(0) as usize }.min(line.len());
    Some((line, point))
}

unsafe fn collect_arguments(mut words: *mut ffi::WordList) -> Vec<String> {
    let mut result = Vec::new();
    while !words.is_null() {
        let descriptor = unsafe { (*words).word };
        if !descriptor.is_null() {
            let word = unsafe { (*descriptor).word };
            if !word.is_null() {
                result.push(
                    unsafe { CStr::from_ptr(word) }
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        words = unsafe { (*words).next };
    }
    result
}

fn lock_state() -> MutexGuard<'static, Option<PluginState>> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn original_redisplay() -> RedisplayFunction {
    let pointer = ORIGINAL_REDISPLAY.load(Ordering::Acquire);
    if pointer == 0 {
        ffi::rl_redisplay
    } else {
        unsafe { std::mem::transmute::<usize, RedisplayFunction>(pointer) }
    }
}

fn original_startup() -> Option<ffi::ReadlineHook> {
    let pointer = ORIGINAL_STARTUP.load(Ordering::Acquire);
    (pointer != 0).then(|| unsafe { std::mem::transmute::<usize, ffi::ReadlineHook>(pointer) })
}

fn original_event() -> Option<ffi::ReadlineHook> {
    let pointer = ORIGINAL_EVENT.load(Ordering::Acquire);
    (pointer != 0).then(|| unsafe { std::mem::transmute::<usize, ffi::ReadlineHook>(pointer) })
}

const PENDING_EVENT_INPUT_TIMEOUT_US: i32 = 5_000;

unsafe fn restore_event_input_timeout() {
    let previous = EVENT_INPUT_TIMEOUT.swap(-1, Ordering::AcqRel);
    if previous >= 0 {
        unsafe { ffi::rl_set_keyboard_input_timeout(previous) };
    }
}

unsafe fn configure_event_hook(required: bool, fast_poll: bool) {
    let current = unsafe { ffi::rl_event_hook };
    let is_ours =
        current.is_some_and(|function| function as usize == event_callback as *const () as usize);
    if !is_ours {
        unsafe { restore_event_input_timeout() };
    }
    if required && !is_ours {
        let original = ORIGINAL_EVENT.load(Ordering::Acquire);
        let current_is_original =
            current.map_or(original == 0, |function| function as usize == original);
        if current_is_original {
            if fast_poll {
                let previous =
                    unsafe { ffi::rl_set_keyboard_input_timeout(PENDING_EVENT_INPUT_TIMEOUT_US) };
                EVENT_INPUT_TIMEOUT.store(previous, Ordering::Release);
            }
            unsafe { ffi::rl_event_hook = Some(event_callback) };
        }
    } else if required && is_ours {
        if fast_poll && EVENT_INPUT_TIMEOUT.load(Ordering::Acquire) < 0 {
            let previous =
                unsafe { ffi::rl_set_keyboard_input_timeout(PENDING_EVENT_INPUT_TIMEOUT_US) };
            EVENT_INPUT_TIMEOUT.store(previous, Ordering::Release);
        } else if !fast_poll {
            unsafe { restore_event_input_timeout() };
        }
    } else if !required && is_ours {
        unsafe { ffi::rl_event_hook = original_event() };
        unsafe { restore_event_input_timeout() };
    }
}

fn call_original_redisplay() {
    unsafe { original_redisplay()() };
}

fn mark_active() -> bool {
    let pointer = MARK_ACTIVE_FUNCTION.load(Ordering::Acquire);
    if pointer == 0 {
        return false;
    }
    let function = unsafe { std::mem::transmute::<usize, unsafe extern "C" fn() -> i32>(pointer) };
    unsafe { function() != 0 }
}

fn write_clear_to_end() {
    let sequence = b"\x1b[0m\x1b[J";
    unsafe {
        ffi::write(
            libc::STDERR_FILENO,
            sequence.as_ptr().cast(),
            sequence.len(),
        );
    }
}

unsafe extern "C" fn mark_forked_child() {
    unsafe { crate::completion::restore_probe_signal_mask_after_fork() };
    FORKED_CHILD.store(true, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::matcher::{CandidateKind, MatchClass};

    #[test]
    fn menu_identity_includes_the_readline_cursor_point() {
        let menu = MenuState {
            line: "echo value".into(),
            point: 10,
            candidates: Vec::new(),
            selected: 0,
            pending: false,
        };
        assert!(menu.matches_context("echo value", 10));
        assert!(!menu.matches_context("echo value", 5));
        assert!(!menu.matches_context("echo other", 10));
    }

    #[test]
    fn accepts_one_shell_word_from_history_suffix() {
        assert_eq!(next_shell_word_length(" status --short"), " status".len());
        assert_eq!(
            next_shell_word_length("/long/path rest"),
            "/long/path".len()
        );
        assert_eq!(
            next_shell_word_length(" \"two words\" tail"),
            " \"two words\"".len()
        );
    }

    #[test]
    fn candidate_ghost_never_uses_fuzzy_only_matches() {
        let context = CompletionContext::analyze("gt", 2);
        let candidate = Candidate {
            display: "git".into(),
            value: "git".into(),
            description: None,
            source_mask: 0,
            kind: CandidateKind::Command,
            append_space: true,
            score: 0,
            match_class: MatchClass::Fuzzy,
            preserve_order: false,
            insertion_order: u64::MAX,
        };
        assert!(ghost_for_candidate(&context, &candidate).is_none());
    }
}
