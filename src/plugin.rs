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
use crate::syntax::{CommandClass, HighlightResult, SyntaxEngine};

static STATE: Mutex<Option<PluginState>> = Mutex::new(None);
static ORIGINAL_REDISPLAY: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_STARTUP: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_EVENT: AtomicUsize = AtomicUsize::new(0);
static EVENT_INPUT_TIMEOUT: AtomicI32 = AtomicI32::new(-1);
static INSTALLED_EVENT_TIMEOUT: AtomicI32 = AtomicI32::new(-1);
static EVENT_HOOK_OWNERSHIP: AtomicUsize = AtomicUsize::new(0);
static MARK_ACTIVE_FUNCTION: AtomicUsize = AtomicUsize::new(0);
static FORKED_CHILD: AtomicBool = AtomicBool::new(false);
static ATFORK_REGISTERED: AtomicBool = AtomicBool::new(false);
static MODULE_PIN_HANDLE: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_DEPTH: AtomicUsize = AtomicUsize::new(0);
static UNLOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

struct CallbackGuard;

impl CallbackGuard {
    fn enter() -> Self {
        CALLBACK_DEPTH.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        if CALLBACK_DEPTH.fetch_sub(1, Ordering::AcqRel) == 1
            && UNLOAD_REQUESTED.swap(false, Ordering::AcqRel)
        {
            unsafe { finish_unload() };
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
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

impl Action {
    fn from_ffi(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::CompleteForward),
            1 => Some(Self::CompleteBackward),
            2 => Some(Self::AcceptAll),
            3 => Some(Self::AcceptWord),
            4 => Some(Self::EndOrAccept),
            5 => Some(Self::Enter),
            6 => Some(Self::OperateAndGetNext),
            7 => Some(Self::PrefetchSpace),
            8 => Some(Self::Cancel),
            _ => None,
        }
    }
}

#[repr(C)]
pub(crate) struct EventTrampolineContext {
    ownership: usize,
    previous_timeout: i32,
    installed_timeout: i32,
}

unsafe extern "C" {
    fn bashlume_complete_forward_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_complete_backward_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_accept_all_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_accept_word_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_end_or_accept_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_enter_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_operate_and_get_next_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_insert_space_and_prefetch_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_cancel_trampoline(count: i32, key: i32) -> i32;
    fn bashlume_redisplay_trampoline();
    fn bashlume_startup_trampoline() -> i32;
    fn bashlume_event_trampoline() -> i32;
}

const REQUEST_FALLBACK: i32 = i32::MIN;

#[derive(Clone)]
struct SavedBinding {
    map: usize,
    sequence: Vec<u8>,
    lookup_sequence: Vec<u8>,
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
    pending_since: Option<Instant>,
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
    shell_stale: bool,
    completion: CompletionEngine,
    syntax: Option<SyntaxEngine>,
    syntax_attempted: bool,
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
        // Readline's startup hook refreshes the authoritative Bash snapshot
        // before the first editable prompt. Avoid taking the same expensive
        // FFI snapshot once here and again a few milliseconds later.
        let shell = ShellSnapshot::default();
        let mut completion = CompletionEngine::new(config.cache_limit_bytes, config.max_candidates);
        completion.configure_rules(
            config.rule_paths.clone(),
            config.trusted_rule_key_paths.clone(),
        );
        Ok(Self {
            enabled: config.enabled,
            config,
            shell,
            shell_stale: true,
            completion,
            syntax: None,
            syntax_attempted: false,
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
        // Prompt display itself does not consume Bash state. Mark the snapshot
        // stale and refresh it on the first edit or completion request, so an
        // idle shell reaches its first prompt without paying synchronous FFI,
        // PATH, and account-snapshot setup costs.
        self.shell_stale = true;
        self.menu = None;
        self.last_ghost = None;
        self.last_dynamic_context = None;
        self.diagnostic_due = None;
        unsafe { self.sync_event_hook() };
    }

    unsafe fn ensure_shell_snapshot(&mut self) {
        if !self.shell_stale {
            return;
        }
        unsafe { self.shell.refresh() };
        self.completion.refresh(&self.shell);
        self.shell_stale = false;
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
        if !self.config.ghost_enabled {
            self.last_ghost = None;
        }
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
        let pending_since = result.pending.then(|| {
            self.menu
                .as_ref()
                .filter(|menu| menu.matches_context(line, context.point) && menu.pending)
                .and_then(|menu| menu.pending_since)
                .unwrap_or_else(Instant::now)
        });
        self.menu = Some(MenuState {
            line: line.to_owned(),
            point: context.point,
            candidates: result.candidates,
            selected,
            pending: result.pending,
            pending_since,
        });
        changed
    }

    fn completion_context(&self, line: &str, point: usize) -> CompletionContext {
        CompletionContext::analyze_with_interactive_comments(
            line,
            point,
            !self.shell.interactive_comments_disabled,
        )
    }

    unsafe fn poll_pending_menu(&mut self) -> bool {
        if !self.menu.as_ref().is_some_and(|menu| menu.pending) {
            return false;
        }
        let Some((line, point)) = (unsafe { readline_line() }) else {
            return false;
        };
        let context = self.completion_context(&line, point);
        self.refresh_menu(&line, &context)
    }

    unsafe fn sync_event_hook(&self) {
        let menu_pending = self.enabled && self.menu.as_ref().is_some_and(|menu| menu.pending);
        let fast_menu_poll = menu_pending
            && self.menu.as_ref().is_some_and(|menu| {
                menu.pending_since
                    .is_some_and(|since| since.elapsed() < FAST_MENU_POLL_WINDOW)
            });
        let completion_pending = self.completion.background_pending() || menu_pending;
        let diagnostic_pending = self.enabled && self.diagnostic_due.is_some();
        unsafe {
            configure_event_hook(
                completion_pending || diagnostic_pending,
                completion_pending,
                fast_menu_poll,
            )
        };
    }

    unsafe fn render(&mut self) {
        if !self.enabled {
            return;
        }
        let Some((line, point)) = (unsafe { readline_line() }) else {
            return;
        };
        if !line.is_empty() || self.menu.is_some() {
            unsafe { self.ensure_shell_snapshot() };
        }
        let context = self.completion_context(&line, point);
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

        if !vi_command_mode && self.config.ghost_enabled {
            self.last_ghost = self
                .menu
                .as_ref()
                .and_then(|menu| menu.candidates.get(menu.selected))
                .and_then(|candidate| ghost_for_candidate(&context, candidate))
                .or_else(|| unsafe {
                    self.completion
                        .ghost(&context, &self.shell, self.config.max_candidates)
                });
        } else {
            self.last_ghost = None;
        }

        if !self.syntax_attempted && !line.is_empty() {
            self.syntax_attempted = true;
            self.syntax = SyntaxEngine::new().ok();
        }
        let shell = &self.shell;
        let completion = &self.completion;
        let highlighted = self.syntax.as_mut().map_or_else(
            || HighlightResult {
                styles: vec![crate::syntax::Style::Normal; line.len()],
                diagnostic: None,
                changed_at: Instant::now(),
            },
            |syntax| {
                syntax.highlight(&line, |command| {
                    if command.contains('/') {
                        return CommandClass::Pending;
                    }
                    match shell.known_shell_command(command) {
                        Some(
                            KnownCommand::Alias | KnownCommand::Function | KnownCommand::Builtin,
                        ) => CommandClass::Builtin,
                        None => match completion.command_known(command) {
                            Some(true) => CommandClass::Valid,
                            Some(false) => CommandClass::Unknown,
                            None => CommandClass::Pending,
                        },
                    }
                })
            },
        );

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
        unsafe { self.ensure_shell_snapshot() };
        let dynamic_context = (line.clone(), point);
        if self.last_dynamic_context.as_ref() != Some(&dynamic_context) {
            self.completion.cancel_dynamic();
            self.last_dynamic_context = Some(dynamic_context);
        }
        let mut context = self.completion_context(&line, point);
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
                pending_since: result.pending.then(Instant::now),
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
                pending_since: Some(Instant::now()),
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
                if let Some(base) = partial.value.strip_suffix(partial.display.as_ref()) {
                    partial.value = format!("{base}{common}").into();
                    partial.display = common.into();
                    partial.append_space = false;
                    unsafe { apply_candidate(&context, &partial) };
                    if let Some((new_line, new_point)) = unsafe { readline_line() } {
                        let dynamic_context = (new_line.clone(), new_point);
                        if self.last_dynamic_context.as_ref() != Some(&dynamic_context) {
                            self.completion.cancel_dynamic();
                            self.last_dynamic_context = Some(dynamic_context);
                        }
                        context = self.completion_context(&new_line, new_point);
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
            pending_since: result.pending.then(Instant::now),
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
                            let context = self.completion_context(&line, point);
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
        let binding = sequence
            .and_then(|sequence| {
                self.bindings.iter().find(|binding| {
                    binding.action == action
                        && binding.map == map
                        && (binding.sequence == sequence || binding.lookup_sequence == sequence)
                })
            })
            .or_else(|| {
                self.bindings.iter().find(|binding| {
                    binding.action == action
                        && binding.map == map
                        && binding.sequence.len() == 1
                        && i32::from(binding.sequence[0]) == key
                })
            });
        let Some(binding) = binding else {
            // An explicitly invoked BashLume defun has no installed binding to
            // restore, so use the action's stable native equivalent.
            return named_fallback(action);
        };
        match binding.original {
            Some(original) if !is_bashlume_wrapper(original) => Some(original),
            Some(_) => named_fallback(action),
            // Preserve a key that was genuinely unbound before BashLume.
            None => None,
        }
    }
}

fn is_bashlume_wrapper(function: ReadlineCommand) -> bool {
    if [
        bashlume_complete_forward_trampoline as ReadlineCommand,
        bashlume_complete_backward_trampoline,
        bashlume_accept_all_trampoline,
        bashlume_end_or_accept_trampoline,
        bashlume_accept_word_trampoline,
        bashlume_enter_trampoline,
        bashlume_operate_and_get_next_trampoline,
        bashlume_insert_space_and_prefetch_trampoline,
        bashlume_cancel_trampoline,
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

fn is_plain_space_self_insert(function: ReadlineCommand, key: i32) -> bool {
    if key != i32::from(b' ') {
        return false;
    }
    let self_insert = unsafe { ffi::rl_named_function(c"self-insert".as_ptr()) };
    if self_insert.map(|command| command as usize) != Some(function as usize) {
        return false;
    }
    let sequence = unsafe { ffi::rl_executing_keyseq };
    !sequence.is_null() && unsafe { CStr::from_ptr(sequence) }.to_bytes() == b" "
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
        if UNLOAD_REQUESTED.load(Ordering::Acquire) {
            return Err("BashLume unload is pending until the active callback returns".into());
        }
        return Ok(());
    }
    let mut state = unsafe { PluginState::new()? };

    let original_redisplay = unsafe { ffi::rl_redisplay_function }.unwrap_or(ffi::rl_redisplay);
    if original_redisplay as usize == bashlume_redisplay_trampoline as *const () as usize {
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
    let mark_active = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"rl_mark_active_p".as_ptr()) };
    MARK_ACTIVE_FUNCTION.store(mark_active as usize, Ordering::Release);
    FORKED_CHILD.store(false, Ordering::Release);
    // Publish complete state before making any Readline hook reachable. A hook
    // may run immediately during a reentrant Readline operation.
    *guard = Some(state);
    drop(guard);
    unsafe {
        ffi::rl_redisplay_function = Some(bashlume_redisplay_trampoline);
        ffi::rl_startup_hook = Some(bashlume_startup_trampoline);
        configure_event_hook(false, false, false);
    }
    Ok(())
}

pub unsafe fn unload() {
    // Invalidate callback ownership immediately, but never tear down STATE or
    // bindings from inside a Readline callback that is still executing Rust.
    EVENT_HOOK_OWNERSHIP.fetch_add(1, Ordering::AcqRel);
    UNLOAD_REQUESTED.store(true, Ordering::Release);
    if CALLBACK_DEPTH.load(Ordering::Acquire) != 0 {
        return;
    }
    if UNLOAD_REQUESTED.swap(false, Ordering::AcqRel) {
        unsafe { finish_unload() };
    }
}

unsafe fn finish_unload() {
    let Some(mut state) = ({
        let mut guard = lock_state();
        guard.take()
    }) else {
        return;
    };
    let forked_child = FORKED_CHILD.load(Ordering::Acquire);

    // Remove process-global callbacks before stopping workers or invoking any
    // Readline binding API. STATE is already unlocked and empty, so an
    // out-of-band callback cannot observe half-torn-down plugin state.
    let original = original_redisplay();
    if unsafe { ffi::rl_redisplay_function }.is_some_and(|function| {
        function as usize == bashlume_redisplay_trampoline as *const () as usize
    }) {
        unsafe { ffi::rl_redisplay_function = Some(original) };
    }
    if unsafe { ffi::rl_startup_hook }.is_some_and(|function| {
        function as usize == bashlume_startup_trampoline as *const () as usize
    }) {
        unsafe { ffi::rl_startup_hook = original_startup() };
    }
    if unsafe { ffi::rl_event_hook }.is_some_and(|function| {
        function as usize == bashlume_event_trampoline as *const () as usize
    }) {
        unsafe { configure_event_hook(false, false, false) };
    } else {
        unsafe { restore_event_input_timeout() };
    }
    if !forked_child {
        state.completion.stop();
    }
    unsafe { restore_bindings(&state.bindings) };
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

#[unsafe(no_mangle)]
pub extern "C" fn bashlume_prepare_redisplay() -> RedisplayFunction {
    original_redisplay()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_finish_redisplay() {
    let _callback_guard = CallbackGuard::enter();
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

#[unsafe(no_mangle)]
pub extern "C" fn bashlume_prepare_startup() -> Option<ffi::ReadlineHook> {
    original_startup()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_finish_startup() {
    let _callback_guard = CallbackGuard::enter();
    if !FORKED_CHILD.load(Ordering::Acquire) {
        let _ = std::panic::catch_unwind(|| {
            if let Some(state) = lock_state().as_mut() {
                unsafe { state.refresh_prompt() };
            }
        });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_prepare_event(
    context: *mut EventTrampolineContext,
) -> Option<ffi::ReadlineHook> {
    let context = (unsafe { context.as_mut() })?;
    context.previous_timeout = EVENT_INPUT_TIMEOUT.load(Ordering::Acquire);
    context.installed_timeout = INSTALLED_EVENT_TIMEOUT.load(Ordering::Acquire);
    context.ownership = EVENT_HOOK_OWNERSHIP.load(Ordering::Acquire);
    if context.previous_timeout >= 0 && context.installed_timeout >= 0 {
        let actual = unsafe { ffi::rl_set_keyboard_input_timeout(context.previous_timeout) };
        if actual != context.installed_timeout {
            EVENT_INPUT_TIMEOUT.store(actual, Ordering::Release);
            unsafe { ffi::rl_set_keyboard_input_timeout(actual) };
        }
    }
    original_event()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_finish_event(
    context: *const EventTrampolineContext,
    status: i32,
    redraw: *mut i32,
) -> i32 {
    let _callback_guard = CallbackGuard::enter();
    if let Some(redraw) = unsafe { redraw.as_mut() } {
        *redraw = 0;
    }
    let Some(context) = (unsafe { context.as_ref() }) else {
        return status;
    };
    let event_hook_is_ours = unsafe { ffi::rl_event_hook }.is_some_and(|function| {
        function as usize == bashlume_event_trampoline as *const () as usize
    });
    if context.previous_timeout >= 0
        && event_timeout_ownership_unchanged(
            context.ownership,
            context.installed_timeout,
            EVENT_HOOK_OWNERSHIP.load(Ordering::Acquire),
            INSTALLED_EVENT_TIMEOUT.load(Ordering::Acquire),
            event_hook_is_ours,
        )
    {
        let updated = unsafe { ffi::rl_set_keyboard_input_timeout(context.installed_timeout) };
        EVENT_INPUT_TIMEOUT.store(updated, Ordering::Release);
    }
    if !unsafe { event_callback_still_owned(context.ownership) } {
        return status;
    }
    if FORKED_CHILD.load(Ordering::Acquire) {
        unsafe { configure_event_hook(false, false, false) };
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
        unsafe { configure_event_hook(true, true, false) };
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
            unsafe { configure_event_hook(false, false, false) };
            eprintln!("bashlume: asynchronous redraw failed; falling back to native Readline");
            false
        }
    };
    if should_redraw {
        if let Some(redraw) = unsafe { redraw.as_mut() } {
            *redraw = 1;
        }
    }
    status
}

#[inline(never)]
unsafe fn invoke_enabled_action(
    state: &mut PluginState,
    action: Action,
    count: i32,
    key: i32,
) -> i32 {
    match action {
        Action::CompleteForward => unsafe { state.complete(false) },
        Action::CompleteBackward => unsafe { state.complete(true) },
        Action::AcceptAll => unsafe { state.accept_all(Action::AcceptAll, count, key) },
        Action::AcceptWord => unsafe { state.accept_word(count, key) },
        Action::EndOrAccept => unsafe { state.accept_all(Action::EndOrAccept, count, key) },
        Action::Enter => unsafe { state.enter(count, key) },
        Action::OperateAndGetNext => unsafe {
            state.accept_command(Action::OperateAndGetNext, count, key)
        },
        Action::PrefetchSpace => REQUEST_FALLBACK,
        Action::Cancel => unsafe { state.cancel(count, key) },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_prepare_action(
    action: i32,
    count: i32,
    key: i32,
    status: *mut i32,
    prefetch_space: *mut i32,
    unbound: *mut i32,
) -> Option<ReadlineCommand> {
    let _callback_guard = CallbackGuard::enter();
    if let Some(status) = unsafe { status.as_mut() } {
        *status = 0;
    }
    if let Some(prefetch_space) = unsafe { prefetch_space.as_mut() } {
        *prefetch_space = 0;
    }
    if let Some(unbound) = unsafe { unbound.as_mut() } {
        *unbound = 0;
    }
    let action = Action::from_ffi(action)?;
    enum Prepared {
        Return(i32),
        Fallback(Option<ReadlineCommand>),
    }

    let forked_child = FORKED_CHILD.load(Ordering::Acquire);
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        let Some(state) = guard.as_mut() else {
            return Prepared::Fallback(named_fallback(action));
        };
        let result = if forked_child || !state.enabled || action == Action::PrefetchSpace {
            REQUEST_FALLBACK
        } else {
            unsafe { invoke_enabled_action(state, action, count, key) }
        };
        if result == REQUEST_FALLBACK {
            Prepared::Fallback(unsafe { state.fallback_function(action, key) })
        } else {
            Prepared::Return(result)
        }
    }))
    .unwrap_or(Prepared::Return(0));

    match prepared {
        Prepared::Return(result) => {
            if let Some(status) = unsafe { status.as_mut() } {
                *status = result;
            }
            None
        }
        Prepared::Fallback(function) => {
            if function.is_none() {
                if let Some(unbound) = unsafe { unbound.as_mut() } {
                    *unbound = 1;
                }
            }
            let should_prefetch = !forked_child
                && function.is_some_and(|function| {
                    action == Action::PrefetchSpace && is_plain_space_self_insert(function, key)
                });
            if should_prefetch {
                if let Some(prefetch_space) = unsafe { prefetch_space.as_mut() } {
                    *prefetch_space = 1;
                }
            }
            function
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_prepare_space_prefetch(
    _count: i32,
    key: i32,
    status: *mut i32,
    prefetch_space: *mut i32,
    unbound: *mut i32,
) -> Option<ReadlineCommand> {
    let _callback_guard = CallbackGuard::enter();
    if let Some(status) = unsafe { status.as_mut() } {
        *status = 0;
    }
    if let Some(prefetch_space) = unsafe { prefetch_space.as_mut() } {
        *prefetch_space = 0;
    }
    if let Some(unbound) = unsafe { unbound.as_mut() } {
        *unbound = 0;
    }
    let forked_child = FORKED_CHILD.load(Ordering::Acquire);
    let function = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        guard.as_mut().map_or_else(
            || named_fallback(Action::PrefetchSpace),
            |state| unsafe { state.fallback_function(Action::PrefetchSpace, key) },
        )
    }))
    .unwrap_or(None);
    if function.is_none() {
        if let Some(unbound) = unsafe { unbound.as_mut() } {
            *unbound = 1;
        }
    }
    if !forked_child && function.is_some_and(|function| is_plain_space_self_insert(function, key)) {
        if let Some(prefetch_space) = unsafe { prefetch_space.as_mut() } {
            *prefetch_space = 1;
        }
    }
    function
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_finish_space_prefetch() {
    let _callback_guard = CallbackGuard::enter();
    if FORKED_CHILD.load(Ordering::Acquire) {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = lock_state();
        let Some(state) = guard.as_mut().filter(|state| state.enabled) else {
            return;
        };
        if let Some((line, point)) = unsafe { readline_line() } {
            let context = state.completion_context(&line, point);
            state.completion.prefetch_rules(&context);
            unsafe { state.sync_event_hook() };
        }
    }));
}

unsafe fn translate_key_sequence(sequence: &CStr) -> Option<Vec<u8>> {
    let input_length = sequence.to_bytes().len();
    let capacity = input_length.checked_mul(2)?.checked_add(1)?;
    let mut output = vec![0_u8; capacity];
    let mut output_length = 0_i32;
    if unsafe {
        ffi::rl_translate_keyseq(
            sequence.as_ptr(),
            output.as_mut_ptr().cast(),
            &mut output_length,
        )
    } != 0
        || output_length < 0
        || output_length as usize >= capacity
    {
        return None;
    }
    output.truncate(output_length as usize);
    Some(output)
}

unsafe fn readline_binding(
    sequence: &[u8],
    map: ffi::Keymap,
    kind: *mut i32,
) -> Option<ReadlineCommand> {
    // Readline 8.0 uses `len` to bound its loop but still checks
    // `keyseq[i + 1]` for the final key. Give every lookup its own explicit
    // terminator so prefix queries are correct and never read another slice.
    let mut terminated = Vec::with_capacity(sequence.len().checked_add(1)?);
    terminated.extend_from_slice(sequence);
    terminated.push(0);
    unsafe { ffi::rl_function_of_keyseq_len(terminated.as_ptr().cast(), sequence.len(), map, kind) }
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
    let Some(translated_sequence) = (unsafe { translate_key_sequence(&sequence_c) }) else {
        return;
    };
    // Installing a longer sequence can replace a function or macro on one of
    // its proper prefixes with a nested keymap. That topology cannot be
    // restored by rebinding only the leaf, so intercept only sequences whose
    // complete translated prefix chain is already composed of keymaps.
    for prefix_length in 1..translated_sequence.len() {
        let mut prefix_kind = ffi::ISFUNC;
        unsafe { readline_binding(&translated_sequence[..prefix_length], map, &mut prefix_kind) };
        if prefix_kind != ffi::ISKMAP {
            return;
        }
    }
    let mut kind = ffi::ISFUNC;
    let original = unsafe { readline_binding(&translated_sequence, map, &mut kind) };
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
            lookup_sequence: translated_sequence,
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
    let Ok(sequence) = CString::new(b" ".as_slice()) else {
        return;
    };
    let Some(translated_sequence) = (unsafe { translate_key_sequence(&sequence) }) else {
        return;
    };
    let mut kind = ffi::ISFUNC;
    let original = unsafe { readline_binding(&translated_sequence, map, &mut kind) };
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
            bashlume_insert_space_and_prefetch_trampoline,
            Action::PrefetchSpace,
        )
    };
}

unsafe fn install_bindings(state: &mut PluginState) {
    let definitions: &[(&CStr, ReadlineCommand)] = &[
        (c"bashlume-complete", bashlume_complete_forward_trampoline),
        (
            c"bashlume-complete-backward",
            bashlume_complete_backward_trampoline,
        ),
        (c"bashlume-accept", bashlume_accept_all_trampoline),
        (c"bashlume-accept-word", bashlume_accept_word_trampoline),
        (c"bashlume-end-or-accept", bashlume_end_or_accept_trampoline),
        (c"bashlume-enter", bashlume_enter_trampoline),
        (
            c"bashlume-operate-and-get-next",
            bashlume_operate_and_get_next_trampoline,
        ),
        (
            c"bashlume-prefetch-space",
            bashlume_insert_space_and_prefetch_trampoline,
        ),
        (c"bashlume-cancel", bashlume_cancel_trampoline),
    ];
    for (name, function) in definitions {
        unsafe { ffi::rl_add_defun(name.as_ptr(), Some(*function), -1) };
    }

    let editing_bindings: &[(&[u8], ReadlineCommand, Action)] = &[
        (
            b"\t",
            bashlume_complete_forward_trampoline,
            Action::CompleteForward,
        ),
        (
            b"\x1b[Z",
            bashlume_complete_backward_trampoline,
            Action::CompleteBackward,
        ),
        (b"\x1b[C", bashlume_accept_all_trampoline, Action::AcceptAll),
        (b"\x1bOC", bashlume_accept_all_trampoline, Action::AcceptAll),
        (
            b"\x1b[F",
            bashlume_end_or_accept_trampoline,
            Action::EndOrAccept,
        ),
        (
            b"\x1bOF",
            bashlume_end_or_accept_trampoline,
            Action::EndOrAccept,
        ),
        (
            b"\x1b[1;3C",
            bashlume_accept_word_trampoline,
            Action::AcceptWord,
        ),
        (
            b"\x1b\x1b[C",
            bashlume_accept_word_trampoline,
            Action::AcceptWord,
        ),
        (b"\r", bashlume_enter_trampoline, Action::Enter),
        (b"\n", bashlume_enter_trampoline, Action::Enter),
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
        unsafe {
            install_binding(
                state,
                vi_movement,
                sequence,
                bashlume_enter_trampoline,
                Action::Enter,
            )
        };
    }

    let emacs = unsafe { ffi::rl_get_keymap_by_name(c"emacs-standard".as_ptr()) };
    unsafe {
        install_binding(
            state,
            emacs,
            b"\x0f",
            bashlume_operate_and_get_next_trampoline,
            Action::OperateAndGetNext,
        )
    };
}

unsafe fn restore_bindings(bindings: &[SavedBinding]) {
    for binding in bindings {
        let map = binding.map as ffi::Keymap;
        let current =
            unsafe { readline_binding(&binding.lookup_sequence, map, std::ptr::null_mut()) };
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

// Keep sustained background polling sparse enough not to spin an idle shell.
// A short menu-only window polls faster so an explicit Tab can display an
// already-running completion promptly, but it is still bounded to 1 kHz.
const BACKGROUND_EVENT_INPUT_TIMEOUT_US: i32 = 5_000;
const MENU_EVENT_INPUT_TIMEOUT_US: i32 = 1_000;
const FAST_MENU_POLL_WINDOW: Duration = Duration::from_millis(25);

unsafe fn set_event_input_timeout(timeout: i32) {
    // Timeout bookkeeping is part of event-hook ownership. Increment even for
    // an equal requested value so an outer chained callback cannot overwrite
    // a restoration target established by reentrant configuration.
    EVENT_HOOK_OWNERSHIP.fetch_add(1, Ordering::AcqRel);
    let installed = INSTALLED_EVENT_TIMEOUT.load(Ordering::Acquire);
    let actual = unsafe { ffi::rl_set_keyboard_input_timeout(timeout) };
    if EVENT_INPUT_TIMEOUT.load(Ordering::Acquire) < 0 || actual != installed {
        // Another Readline participant changed the process-global timeout
        // since our last write. Preserve that value as its new restoration
        // target instead of clobbering it when BashLume becomes idle.
        EVENT_INPUT_TIMEOUT.store(actual, Ordering::Release);
    }
    INSTALLED_EVENT_TIMEOUT.store(timeout, Ordering::Release);
}

unsafe fn restore_event_input_timeout() {
    EVENT_HOOK_OWNERSHIP.fetch_add(1, Ordering::AcqRel);
    let previous = EVENT_INPUT_TIMEOUT.swap(-1, Ordering::AcqRel);
    let installed = INSTALLED_EVENT_TIMEOUT.swap(-1, Ordering::AcqRel);
    if previous >= 0 {
        let actual = unsafe { ffi::rl_set_keyboard_input_timeout(previous) };
        if installed >= 0 && actual != installed {
            // An out-of-band owner wrote a newer timeout. The setter is the
            // only public Readline API that reports the current value, so put
            // that intervening value back after observing it.
            unsafe { ffi::rl_set_keyboard_input_timeout(actual) };
        }
    }
}

fn event_callback_ownership_unchanged(
    captured_ownership: usize,
    current_ownership: usize,
    event_hook_is_ours: bool,
) -> bool {
    captured_ownership == current_ownership && event_hook_is_ours
}

unsafe fn event_callback_still_owned(captured_ownership: usize) -> bool {
    let event_hook_is_ours = unsafe { ffi::rl_event_hook }.is_some_and(|function| {
        function as usize == bashlume_event_trampoline as *const () as usize
    });
    event_callback_ownership_unchanged(
        captured_ownership,
        EVENT_HOOK_OWNERSHIP.load(Ordering::Acquire),
        event_hook_is_ours,
    )
}

fn event_timeout_ownership_unchanged(
    captured_ownership: usize,
    captured_timeout: i32,
    current_ownership: usize,
    current_timeout: i32,
    event_hook_is_ours: bool,
) -> bool {
    event_hook_is_ours
        && captured_ownership == current_ownership
        && captured_timeout >= 0
        && current_timeout == captured_timeout
}

unsafe fn configure_event_hook(required: bool, fast_poll: bool, menu_pending: bool) {
    let current = unsafe { ffi::rl_event_hook };
    let is_ours = current.is_some_and(|function| {
        function as usize == bashlume_event_trampoline as *const () as usize
    });
    if !is_ours {
        unsafe { restore_event_input_timeout() };
    }
    if required && !is_ours {
        let original = ORIGINAL_EVENT.load(Ordering::Acquire);
        let current_is_original =
            current.map_or(original == 0, |function| function as usize == original);
        if current_is_original {
            if fast_poll {
                let timeout = if menu_pending {
                    MENU_EVENT_INPUT_TIMEOUT_US
                } else {
                    BACKGROUND_EVENT_INPUT_TIMEOUT_US
                };
                unsafe { set_event_input_timeout(timeout) };
            }
            unsafe { ffi::rl_event_hook = Some(bashlume_event_trampoline) };
            EVENT_HOOK_OWNERSHIP.fetch_add(1, Ordering::AcqRel);
        }
    } else if required && is_ours {
        if fast_poll {
            let timeout = if menu_pending {
                MENU_EVENT_INPUT_TIMEOUT_US
            } else {
                BACKGROUND_EVENT_INPUT_TIMEOUT_US
            };
            unsafe { set_event_input_timeout(timeout) };
        } else {
            unsafe { restore_event_input_timeout() };
        }
    } else if !required && is_ours {
        EVENT_HOOK_OWNERSHIP.fetch_add(1, Ordering::AcqRel);
        unsafe { ffi::rl_event_hook = original_event() };
        unsafe { restore_event_input_timeout() };
    }
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
            pending_since: None,
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
    fn reentrant_unload_invalidates_a_captured_event_timeout() {
        assert!(event_callback_ownership_unchanged(7, 7, true));
        assert!(!event_callback_ownership_unchanged(7, 8, true));
        assert!(!event_callback_ownership_unchanged(7, 7, false));
        assert!(event_timeout_ownership_unchanged(7, 250, 7, 250, true));
        assert!(!event_timeout_ownership_unchanged(7, 250, 8, -1, false));
        assert!(!event_timeout_ownership_unchanged(7, 250, 7, 5_000, true));
        assert!(!event_timeout_ownership_unchanged(7, 250, 7, 250, false));
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
