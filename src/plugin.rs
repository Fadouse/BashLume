use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
static MARK_ACTIVE_FUNCTION: AtomicUsize = AtomicUsize::new(0);
static FORKED_CHILD: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    CompleteForward,
    CompleteBackward,
    AcceptAll,
    AcceptWord,
    EndOrAccept,
    Enter,
    Cancel,
}

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
    candidates: Vec<Candidate>,
    selected: usize,
    pending: bool,
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
            diagnostic_due: None,
        })
    }

    unsafe fn refresh_prompt(&mut self) {
        self.completion.cancel_dynamic();
        unsafe { self.shell.refresh() };
        self.completion.refresh(&self.shell);
        self.menu = None;
        self.last_ghost = None;
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
            menu.line != line
                || menu.selected != selected
                || menu.pending != result.pending
                || menu.candidates != result.candidates
        });
        self.menu = Some(MenuState {
            line: line.to_owned(),
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
        let required = self.enabled
            && (self.menu.as_ref().is_some_and(|menu| menu.pending)
                || self.diagnostic_due.is_some());
        unsafe { configure_event_hook(required) };
    }

    unsafe fn render(&mut self) {
        if !self.enabled {
            return;
        }
        let Some((line, point)) = (unsafe { readline_line() }) else {
            return;
        };
        let context = CompletionContext::analyze(&line, point);
        let vi_command_mode = unsafe { in_vi_command_mode() };
        if vi_command_mode {
            self.menu = None;
            self.last_ghost = None;
        }

        let menu_line_changed = self.menu.as_ref().is_some_and(|menu| menu.line != line);
        if menu_line_changed {
            self.completion.cancel_dynamic();
        }
        let refresh_menu = self
            .menu
            .as_ref()
            .is_some_and(|menu| menu.line != line || menu.pending);
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
            return unsafe {
                self.call_fallback(
                    if backwards {
                        Action::CompleteBackward
                    } else {
                        Action::CompleteForward
                    },
                    1,
                    b'\t' as i32,
                )
            };
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
            return unsafe {
                self.call_fallback(
                    if backwards {
                        Action::CompleteBackward
                    } else {
                        Action::CompleteForward
                    },
                    1,
                    b'\t' as i32,
                )
            };
        };
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

        let current_line = unsafe { readline_line() }
            .map(|(line, _)| line)
            .unwrap_or(line);
        self.menu = Some(MenuState {
            line: current_line,
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
        unsafe { self.call_fallback(fallback, count, key) }
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
        unsafe { self.call_fallback(Action::AcceptWord, count, key) }
    }

    unsafe fn enter(&mut self, count: i32, key: i32) -> i32 {
        if self.enabled {
            if let Some(menu) = self.menu.take() {
                if let Some(candidate) = menu.candidates.get(menu.selected) {
                    if let Some((line, point)) = unsafe { readline_line() } {
                        let context = CompletionContext::analyze(&line, point);
                        unsafe { apply_candidate(&context, candidate) };
                        self.last_ghost = None;
                        return 0;
                    }
                }
            }
            if let Some((line, point)) = unsafe { readline_line() } {
                unsafe { self.renderer.clear_extras(&line, point) };
            }
            self.last_ghost = None;
        }
        unsafe { self.call_fallback(Action::Enter, count, key) }
    }

    unsafe fn cancel(&mut self, count: i32, key: i32) -> i32 {
        if self.menu.take().is_some() {
            self.completion.cancel_dynamic();
            self.last_ghost = None;
            unsafe { self.sync_event_hook() };
            return 0;
        }
        unsafe { self.call_fallback(Action::Cancel, count, key) }
    }

    unsafe fn call_fallback(&self, action: Action, count: i32, key: i32) -> i32 {
        let map = unsafe { ffi::rl_get_keymap() } as usize;
        if let Some(function) = self
            .bindings
            .iter()
            .find(|binding| binding.action == action && binding.map == map)
            .and_then(|binding| binding.original)
        {
            return unsafe { function(count, key) };
        }
        // Stable Readline defaults for maps where no direct binding existed.
        let name = match action {
            Action::CompleteForward | Action::CompleteBackward => c"complete",
            Action::AcceptAll => c"forward-char",
            Action::AcceptWord => c"forward-word",
            Action::EndOrAccept => c"end-of-line",
            Action::Enter => c"accept-line",
            Action::Cancel => c"abort",
        };
        let function = unsafe { ffi::rl_named_function(name.as_ptr()) };
        function.map_or(0, |function| unsafe { function(count, key) })
    }
}

pub unsafe fn load() -> Result<(), String> {
    if unsafe { ffi::interactive_shell } == 0 {
        return Err("not an interactive Bash shell".into());
    }
    if unsafe { ffi::isatty(libc::STDERR_FILENO) } == 0 {
        return Err("Readline output is not attached to a terminal".into());
    }

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

    unsafe { install_bindings(&mut state) };
    unsafe {
        ffi::rl_redisplay_function = Some(redisplay_callback);
        ffi::rl_startup_hook = Some(startup_callback);
        configure_event_hook(false);
    }
    let mark_active = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"rl_mark_active_p".as_ptr()) };
    MARK_ACTIVE_FUNCTION.store(mark_active as usize, Ordering::Release);
    FORKED_CHILD.store(false, Ordering::Release);
    unsafe {
        libc::pthread_atfork(None, None, Some(mark_forked_child));
    }
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
        unsafe { ffi::rl_event_hook = original_event() };
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
            state.enabled = false;
            state.menu = None;
            state.last_ghost = None;
            state.completion.cancel_dynamic();
            unsafe { state.sync_event_hook() };
            0
        }
        "reload" => {
            unsafe { state.reload_config() };
            0
        }
        "stats" => {
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
        let Some(state) = guard.as_mut().filter(|state| state.enabled) else {
            return false;
        };
        let menu_changed = unsafe { state.poll_pending_menu() };
        let diagnostic_due = state
            .diagnostic_due
            .is_some_and(|deadline| Instant::now() >= deadline);
        menu_changed || diagnostic_due
    })) {
        Ok(changed) => changed,
        Err(_) => {
            if let Some(state) = lock_state().as_mut() {
                state.enabled = false;
            }
            unsafe { configure_event_hook(false) };
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
    if FORKED_CHILD.load(Ordering::Acquire) {
        let guard = lock_state();
        return guard.as_ref().map_or(default, |state| unsafe {
            state.call_fallback(fallback, count, key)
        });
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        let Some(state) = guard.as_mut() else {
            return default;
        };
        if state.enabled {
            callback(state)
        } else {
            unsafe { state.call_fallback(fallback, count, key) }
        }
    }))
    .unwrap_or(default)
}

unsafe fn install_bindings(state: &mut PluginState) {
    let definitions: &[(&CStr, ReadlineCommand)] = &[
        (c"bashlume-complete", complete_forward),
        (c"bashlume-complete-backward", complete_backward),
        (c"bashlume-accept", accept_all),
        (c"bashlume-accept-word", accept_word),
        (c"bashlume-end-or-accept", end_or_accept),
        (c"bashlume-enter", enter),
        (c"bashlume-cancel", cancel),
    ];
    for (name, function) in definitions {
        unsafe { ffi::rl_add_defun(name.as_ptr(), Some(*function), -1) };
    }

    let maps = [c"emacs-standard", c"vi-insertion"];
    let bindings: &[(&[u8], ReadlineCommand, Action)] = &[
        (b"\t", complete_forward, Action::CompleteForward),
        (b"\x1b[Z", complete_backward, Action::CompleteBackward),
        (b"\x1b[C", accept_all, Action::AcceptAll),
        (b"\x1bOC", accept_all, Action::AcceptAll),
        (b"\x1b[F", end_or_accept, Action::EndOrAccept),
        (b"\x1bOF", end_or_accept, Action::EndOrAccept),
        (b"\x1b[1;3C", accept_word, Action::AcceptWord),
        (b"\x1b\x1b[C", accept_word, Action::AcceptWord),
        (b"\r", enter, Action::Enter),
        (b"\x07", cancel, Action::Cancel),
    ];

    for map_name in maps {
        let map = unsafe { ffi::rl_get_keymap_by_name(map_name.as_ptr()) };
        if map.is_null() {
            continue;
        }
        for &(sequence, replacement, action) in bindings {
            let Ok(sequence_c) = CString::new(sequence) else {
                continue;
            };
            let mut kind = ffi::ISFUNC;
            let original = unsafe {
                ffi::rl_function_of_keyseq_len(
                    sequence.as_ptr().cast(),
                    sequence.len(),
                    map,
                    &mut kind,
                )
            };
            let original = (kind == ffi::ISFUNC).then_some(original).flatten();
            if unsafe { ffi::rl_bind_keyseq_in_map(sequence_c.as_ptr(), Some(replacement), map) }
                == 0
            {
                state.bindings.push(SavedBinding {
                    map: map as usize,
                    sequence: sequence.to_vec(),
                    original,
                    replacement,
                    action,
                });
            }
        }
    }
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
    let movement = unsafe { ffi::rl_get_keymap_by_name(c"vi-movement".as_ptr()) };
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

unsafe fn configure_event_hook(required: bool) {
    let current = unsafe { ffi::rl_event_hook };
    let is_ours =
        current.is_some_and(|function| function as usize == event_callback as *const () as usize);
    if required && !is_ours {
        let original = ORIGINAL_EVENT.load(Ordering::Acquire);
        let current_is_original =
            current.map_or(original == 0, |function| function as usize == original);
        if current_is_original {
            unsafe { ffi::rl_event_hook = Some(event_callback) };
        }
    } else if !required && is_ours {
        unsafe { ffi::rl_event_hook = original_event() };
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
    FORKED_CHILD.store(true, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::matcher::{CandidateKind, MatchClass};

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
        };
        assert!(ghost_for_candidate(&context, &candidate).is_none());
    }
}
