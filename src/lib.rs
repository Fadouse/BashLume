//! BashLume is a small GNU Bash loadable builtin that augments GNU Readline.
//! It deliberately leaves line editing, history search, undo, macros, and
//! Emacs/Vi keymaps under Readline's control.

mod completion;
mod config;
mod ffi;
mod plugin;
mod render;
pub mod rules;
mod shell;
mod syntax;

use libc::{c_char, c_int};

struct SyncPointers([*const c_char; 3]);
unsafe impl Sync for SyncPointers {}

static LONG_DOCUMENTATION: SyncPointers = SyncPointers([
    c"BashLume adds native syntax highlighting and completion to GNU Bash.".as_ptr(),
    c"Run `bashlume help` for runtime controls.".as_ptr(),
    std::ptr::null(),
]);

#[unsafe(no_mangle)]
pub static mut bashlume_struct: ffi::BashBuiltin = ffi::BashBuiltin {
    name: c"bashlume".as_ptr(),
    function: Some(bashlume_command),
    flags: ffi::BUILTIN_ENABLED,
    long_doc: LONG_DOCUMENTATION.0.as_ptr(),
    short_doc: c"bashlume [status|enable|disable|reload|stats|rules|help]".as_ptr(),
    handle: std::ptr::null_mut(),
};

/// Called by Bash immediately after loading `bashlume_struct`.
///
/// # Safety
/// `enable -f` must invoke this on Bash's main thread with Bash and Readline
/// globals initialized according to the loadable builtin ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_builtin_load(_name: *const c_char) -> c_int {
    match std::panic::catch_unwind(|| unsafe { plugin::load() }) {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            eprintln!("bashlume: {error}; using native Readline");
            0
        }
        Err(_) => {
            eprintln!("bashlume: initialization panicked; using native Readline");
            0
        }
    }
}

/// Restores callbacks and key bindings before Bash closes the shared object.
///
/// # Safety
/// Bash must call this on its main thread and must not invoke another
/// BashLume callback concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bashlume_builtin_unload() {
    let _ = std::panic::catch_unwind(|| unsafe { plugin::unload() });
}

unsafe extern "C" fn bashlume_command(arguments: *mut ffi::WordList) -> c_int {
    std::panic::catch_unwind(|| unsafe { plugin::control(arguments) }).unwrap_or_else(|_| {
        eprintln!("bashlume: command failed internally");
        1
    })
}
