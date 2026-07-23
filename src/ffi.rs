//! Narrow, audited FFI boundary to GNU Bash and GNU Readline.
//!
//! BashLume never exposes these raw pointers outside the main shell thread.

use libc::{c_char, c_int, c_ulong, c_void, size_t};

pub type Keymap = *mut c_void;
pub type ReadlineCommand = unsafe extern "C" fn(c_int, c_int) -> c_int;
pub type ReadlineHook = unsafe extern "C" fn() -> c_int;
pub type RedisplayFunction = unsafe extern "C" fn();

#[repr(C)]
pub struct WordDesc {
    pub word: *mut c_char,
    pub flags: c_int,
}

#[repr(C)]
pub struct WordList {
    pub next: *mut WordList,
    pub word: *mut WordDesc,
}

pub type BuiltinFunction = unsafe extern "C" fn(*mut WordList) -> c_int;

#[repr(C)]
pub struct BashBuiltin {
    pub name: *const c_char,
    pub function: Option<BuiltinFunction>,
    pub flags: c_int,
    pub long_doc: *const *const c_char,
    pub short_doc: *const c_char,
    pub handle: *mut c_char,
}

#[repr(C)]
pub struct Alias {
    pub name: *mut c_char,
    pub value: *mut c_char,
    pub flags: c_char,
}

#[repr(C)]
pub struct ShellVar {
    pub name: *mut c_char,
    pub value: *mut c_char,
    pub exportstr: *mut c_char,
    pub dynamic_value: *mut c_void,
    pub assign_func: *mut c_void,
    pub attributes: c_int,
    pub context: c_int,
}

#[repr(C)]
pub struct HistoryEntry {
    pub line: *mut c_char,
    pub timestamp: *mut c_char,
    pub data: *mut c_void,
}

unsafe extern "C" {
    // Readline's public application interface.
    pub static mut rl_line_buffer: *mut c_char;
    pub static mut rl_point: c_int;
    pub static mut rl_end: c_int;
    pub static mut rl_display_prompt: *mut c_char;
    pub static mut rl_redisplay_function: Option<RedisplayFunction>;
    pub static mut rl_startup_hook: Option<ReadlineHook>;
    pub static mut rl_event_hook: Option<ReadlineHook>;
    pub static mut rl_readline_state: c_ulong;

    pub fn rl_redisplay();
    pub fn rl_forced_update_display() -> c_int;
    pub fn rl_insert_text(text: *const c_char) -> c_int;
    pub fn rl_delete_text(start: c_int, end: c_int) -> c_int;
    pub fn rl_begin_undo_group() -> c_int;
    pub fn rl_end_undo_group() -> c_int;
    pub fn rl_ding() -> c_int;

    pub fn rl_add_defun(
        name: *const c_char,
        function: Option<ReadlineCommand>,
        key: c_int,
    ) -> c_int;
    pub fn rl_bind_keyseq_in_map(
        keyseq: *const c_char,
        function: Option<ReadlineCommand>,
        map: Keymap,
    ) -> c_int;
    pub fn rl_function_of_keyseq_len(
        keyseq: *const c_char,
        len: size_t,
        map: Keymap,
        kind: *mut c_int,
    ) -> Option<ReadlineCommand>;
    pub fn rl_get_keymap_by_name(name: *const c_char) -> Keymap;
    pub fn rl_get_keymap() -> Keymap;
    pub fn rl_named_function(name: *const c_char) -> Option<ReadlineCommand>;

    // Bash's stable loadable-builtin-facing symbols.
    pub static interactive_shell: c_int;
    pub static mut shell_builtins: *mut BashBuiltin;
    pub static num_shell_builtins: c_int;

    pub fn find_variable(name: *const c_char) -> *mut ShellVar;
    pub fn all_aliases() -> *mut *mut Alias;
    pub fn all_shell_functions() -> *mut *mut ShellVar;
    pub fn all_variables_matching_prefix(prefix: *const c_char) -> *mut *mut c_char;
    pub fn history_list() -> *mut *mut HistoryEntry;
    pub fn strvec_dispose(values: *mut *mut c_char);

    // libc functions are declared here where their ownership role is explicit.
    pub fn free(pointer: *mut c_void);
    pub fn write(fd: c_int, buffer: *const c_void, count: size_t) -> isize;
    pub fn isatty(fd: c_int) -> c_int;
}

pub const BUILTIN_ENABLED: c_int = 0x01;

pub const RL_STATE_ISEARCH: c_ulong = 0x0000_0080;
pub const RL_STATE_NSEARCH: c_ulong = 0x0000_0100;
pub const RL_STATE_SEARCH: c_ulong = 0x0000_0200;
pub const RL_STATE_MACRODEF: c_ulong = 0x0000_1000;
pub const RL_STATE_COMPLETING: c_ulong = 0x0000_4000;
pub const RL_STATE_SIGHANDLER: c_ulong = 0x0000_8000;

pub const ISFUNC: c_int = 0;
