use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::path::PathBuf;

use crate::ffi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownCommand {
    Alias,
    Function,
    Builtin,
}

#[derive(Debug, Default)]
pub struct ShellSnapshot {
    pub aliases: HashSet<String>,
    pub functions: HashSet<String>,
    pub builtins: HashSet<String>,
    pub variables: Vec<String>,
    pub command_frequency: HashMap<String, (u32, usize)>,
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub path: String,
}

impl ShellSnapshot {
    /// Refreshes data while Bash is idle in Readline's startup hook.
    ///
    /// # Safety
    /// All Bash FFI calls must happen on the shell's main thread.
    pub unsafe fn refresh(&mut self) {
        self.aliases = unsafe { aliases() };
        self.functions = unsafe { functions() };
        self.builtins = unsafe { builtins() };
        self.variables = unsafe { variables() };
        self.cwd = unsafe { shell_variable("PWD") }
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        self.home = unsafe { shell_variable("HOME") }.map(PathBuf::from);
        self.path = unsafe { shell_variable("PATH") }.unwrap_or_default();
        self.command_frequency = unsafe { command_frequency() };
    }

    pub fn known_shell_command(&self, name: &str) -> Option<KnownCommand> {
        if self.aliases.contains(name) {
            Some(KnownCommand::Alias)
        } else if self.functions.contains(name) {
            Some(KnownCommand::Function)
        } else if self.builtins.contains(name) {
            Some(KnownCommand::Builtin)
        } else {
            None
        }
    }

    pub fn command_recency_bonus(&self, name: &str) -> i64 {
        self.command_frequency.get(name).map_or(0, |(count, last)| {
            (*count as i64).min(100) * 20 + (*last as i64).min(500)
        })
    }
}

/// Returns the newest history line that extends `prefix`.
///
/// # Safety
/// Readline's history list must not be mutated during this call.
pub unsafe fn history_suggestion(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let list = unsafe { ffi::history_list() };
    if list.is_null() {
        return None;
    }
    let mut count = 0_usize;
    while !unsafe { *list.add(count) }.is_null() {
        count += 1;
    }
    for index in (0..count).rev() {
        let entry = unsafe { *list.add(index) };
        if entry.is_null() {
            continue;
        }
        let line = unsafe { (*entry).line };
        if line.is_null() {
            continue;
        }
        let line = unsafe { CStr::from_ptr(line) }.to_string_lossy();
        if line.len() > prefix.len() && line.starts_with(prefix) {
            return Some(line.into_owned());
        }
    }
    None
}

/// Reads an ordinary or exported Bash scalar variable.
///
/// # Safety
/// Must execute on Bash's main thread.
pub unsafe fn shell_variable(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let variable = unsafe { ffi::find_variable(name.as_ptr()) };
    if variable.is_null() {
        return None;
    }
    let value = unsafe { (*variable).value };
    if value.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn aliases() -> HashSet<String> {
    let mut result = HashSet::new();
    let values = unsafe { ffi::all_aliases() };
    if values.is_null() {
        return result;
    }
    let mut index = 0_usize;
    loop {
        let alias = unsafe { *values.add(index) };
        if alias.is_null() {
            break;
        }
        let name = unsafe { (*alias).name };
        if !name.is_null() {
            result.insert(
                unsafe { CStr::from_ptr(name) }
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        index += 1;
    }
    unsafe { ffi::free(values.cast()) };
    result
}

unsafe fn functions() -> HashSet<String> {
    let mut result = HashSet::new();
    let values = unsafe { ffi::all_shell_functions() };
    if values.is_null() {
        return result;
    }
    let mut index = 0_usize;
    loop {
        let function = unsafe { *values.add(index) };
        if function.is_null() {
            break;
        }
        let name = unsafe { (*function).name };
        if !name.is_null() {
            result.insert(
                unsafe { CStr::from_ptr(name) }
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        index += 1;
    }
    unsafe { ffi::free(values.cast()) };
    result
}

unsafe fn variables() -> Vec<String> {
    let values = unsafe { ffi::all_variables_matching_prefix(c"".as_ptr()) };
    if values.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut index = 0_usize;
    loop {
        let value = unsafe { *values.add(index) };
        if value.is_null() {
            break;
        }
        result.push(
            unsafe { CStr::from_ptr(value) }
                .to_string_lossy()
                .into_owned(),
        );
        index += 1;
    }
    unsafe { ffi::strvec_dispose(values) };
    result
}

unsafe fn builtins() -> HashSet<String> {
    let mut result = HashSet::new();
    let count = unsafe { ffi::num_shell_builtins.max(0) as usize };
    let values = unsafe { ffi::shell_builtins };
    if values.is_null() {
        return result;
    }
    for index in 0..count {
        let builtin = unsafe { &*values.add(index) };
        if builtin.name.is_null() || builtin.flags & ffi::BUILTIN_ENABLED == 0 {
            continue;
        }
        result.insert(
            unsafe { CStr::from_ptr(builtin.name) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    result
}

unsafe fn command_frequency() -> HashMap<String, (u32, usize)> {
    let mut result = HashMap::new();
    let list = unsafe { ffi::history_list() };
    if list.is_null() {
        return result;
    }
    let mut index = 0_usize;
    loop {
        let entry = unsafe { *list.add(index) };
        if entry.is_null() {
            break;
        }
        let line = unsafe { (*entry).line };
        if !line.is_null() {
            let line = unsafe { CStr::from_ptr(line) }.to_string_lossy();
            if let Some(command) = first_command_word(&line) {
                let item = result.entry(command.to_owned()).or_insert((0_u32, 0_usize));
                item.0 = item.0.saturating_add(1);
                item.1 = index;
            }
        }
        index += 1;
    }
    result
}

fn first_command_word(line: &str) -> Option<&str> {
    line.split(|character: char| character.is_whitespace() || ";|&()".contains(character))
        .find(|word| {
            !word.is_empty()
                && !word
                    .split_once('=')
                    .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frequency_lexer_skips_assignments() {
        assert_eq!(first_command_word("A=1 B=2 env"), Some("env"));
        assert_eq!(first_command_word("  git status"), Some("git"));
    }
}
