use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::path::PathBuf;

use crate::ffi;

const MAX_SNAPSHOT_ITEMS: usize = 4096;
const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_SCALAR_BYTES: usize = 64 * 1024;
const MAX_HISTORY_ITEMS: usize = 8192;
const MAX_HISTORY_BYTES: usize = 1024 * 1024;

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
    pub variable_values: HashMap<String, Vec<String>>,
    pub command_frequency: HashMap<String, (u32, usize)>,
    pub environment: HashMap<String, String>,
    pub cwd: PathBuf,
    pub home: Option<PathBuf>,
    pub path: String,
    pub interactive_comments_disabled: bool,
    pub effective_user_id: u32,
    pub generation: u64,
}

impl ShellSnapshot {
    /// Refreshes data while Bash is idle in Readline's startup hook.
    ///
    /// # Safety
    /// All Bash FFI calls must happen on the shell's main thread.
    pub unsafe fn refresh(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.aliases = unsafe { aliases() };
        self.functions = unsafe { functions() };
        self.builtins = unsafe { builtins() };
        self.variables = unsafe { variables() };
        self.variable_values = unsafe { scalar_variable_values(&self.variables) };
        self.cwd = unsafe { shell_variable("PWD") }
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        self.home = unsafe { shell_variable("HOME") }.map(PathBuf::from);
        self.path = unsafe { shell_variable("PATH") }.unwrap_or_default();
        self.interactive_comments_disabled =
            unsafe { shell_variable("BASHOPTS") }.is_some_and(|options| {
                !options
                    .split(':')
                    .any(|option| option == "interactive_comments")
            });
        self.command_frequency = unsafe { command_frequency() };
        self.environment = environment_snapshot();
        self.effective_user_id = unsafe { libc::geteuid() };
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
    if prefix.is_empty() || prefix.len() > MAX_SCALAR_BYTES {
        return None;
    }
    let list = unsafe { ffi::history_list() };
    if list.is_null() {
        return None;
    }
    let count = usize::try_from(unsafe { ffi::history_length }.max(0)).unwrap_or(0);
    let start = count.saturating_sub(MAX_HISTORY_ITEMS);
    let mut inspected_bytes = 0_usize;
    for index in (start..count).rev() {
        let entry = unsafe { *list.add(index) };
        if entry.is_null() {
            continue;
        }
        let line = unsafe { (*entry).line };
        if line.is_null() {
            continue;
        }
        let line = unsafe { CStr::from_ptr(line) };
        if line.to_bytes().len() > MAX_SCALAR_BYTES
            || inspected_bytes.saturating_add(line.to_bytes().len()) > MAX_HISTORY_BYTES
        {
            break;
        }
        inspected_bytes = inspected_bytes.saturating_add(line.to_bytes().len());
        let line = line.to_string_lossy();
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
    const NON_SCALAR_ATTRIBUTES: i32 = 0x0000_0004 | 0x0000_0008 | 0x0000_0040 | 0x0000_1000;
    if unsafe { (*variable).attributes } & NON_SCALAR_ATTRIBUTES != 0 {
        return None;
    }
    let value = unsafe { (*variable).value };
    if value.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(value) };
    (value.to_bytes().len() <= MAX_SCALAR_BYTES).then(|| value.to_string_lossy().into_owned())
}

fn environment_snapshot() -> HashMap<String, String> {
    let mut result = HashMap::new();
    let mut bytes = 0_usize;
    for (name, value) in std::env::vars_os().take(MAX_SNAPSHOT_ITEMS) {
        let (Ok(name), Ok(value)) = (name.into_string(), value.into_string()) else {
            continue;
        };
        let item_bytes = name.len().saturating_add(value.len());
        if item_bytes > MAX_SCALAR_BYTES || bytes.saturating_add(item_bytes) > MAX_SNAPSHOT_BYTES {
            continue;
        }
        bytes = bytes.saturating_add(item_bytes);
        result.insert(name, value);
    }
    result
}

unsafe fn aliases() -> HashSet<String> {
    let mut result = HashSet::new();
    let values = unsafe { ffi::all_aliases() };
    if values.is_null() {
        return result;
    }
    let mut index = 0_usize;
    let mut bytes = 0_usize;
    while index < MAX_SNAPSHOT_ITEMS {
        let alias = unsafe { *values.add(index) };
        if alias.is_null() {
            break;
        }
        let name = unsafe { (*alias).name };
        if !name.is_null() {
            let name = unsafe { CStr::from_ptr(name) };
            if name.to_bytes().len() <= MAX_SCALAR_BYTES
                && bytes.saturating_add(name.to_bytes().len()) <= MAX_SNAPSHOT_BYTES
            {
                bytes = bytes.saturating_add(name.to_bytes().len());
                result.insert(name.to_string_lossy().into_owned());
            }
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
    let mut bytes = 0_usize;
    while index < MAX_SNAPSHOT_ITEMS {
        let function = unsafe { *values.add(index) };
        if function.is_null() {
            break;
        }
        let name = unsafe { (*function).name };
        if !name.is_null() {
            let name = unsafe { CStr::from_ptr(name) };
            if name.to_bytes().len() <= MAX_SCALAR_BYTES
                && bytes.saturating_add(name.to_bytes().len()) <= MAX_SNAPSHOT_BYTES
            {
                bytes = bytes.saturating_add(name.to_bytes().len());
                result.insert(name.to_string_lossy().into_owned());
            }
        }
        index += 1;
    }
    unsafe { ffi::free(values.cast()) };
    result
}

unsafe fn scalar_variable_values(names: &[String]) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    let mut total = 0_usize;
    for name in names.iter().take(MAX_SNAPSHOT_ITEMS) {
        let Some(value) = (unsafe { shell_variable(name) }) else {
            continue;
        };
        if value.len() > MAX_SCALAR_BYTES
            || total.saturating_add(name.len()).saturating_add(value.len()) > MAX_SNAPSHOT_BYTES
        {
            continue;
        }
        total = total.saturating_add(name.len()).saturating_add(value.len());
        result.insert(name.clone(), vec![value]);
    }
    result
}

unsafe fn variables() -> Vec<String> {
    let values = unsafe { ffi::all_variables_matching_prefix(c"".as_ptr()) };
    if values.is_null() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut index = 0_usize;
    let mut bytes = 0_usize;
    while index < MAX_SNAPSHOT_ITEMS {
        let value = unsafe { *values.add(index) };
        if value.is_null() {
            break;
        }
        let value = unsafe { CStr::from_ptr(value) };
        if value.to_bytes().len() <= MAX_SCALAR_BYTES
            && bytes.saturating_add(value.to_bytes().len()) <= MAX_SNAPSHOT_BYTES
        {
            bytes = bytes.saturating_add(value.to_bytes().len());
            result.push(value.to_string_lossy().into_owned());
        }
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
    let mut bytes = 0_usize;
    for index in 0..count.min(MAX_SNAPSHOT_ITEMS) {
        let builtin = unsafe { &*values.add(index) };
        if builtin.name.is_null() || builtin.flags & ffi::BUILTIN_ENABLED == 0 {
            continue;
        }
        let name = unsafe { CStr::from_ptr(builtin.name) };
        if name.to_bytes().len() <= MAX_SCALAR_BYTES
            && bytes.saturating_add(name.to_bytes().len()) <= MAX_SNAPSHOT_BYTES
        {
            bytes = bytes.saturating_add(name.to_bytes().len());
            result.insert(name.to_string_lossy().into_owned());
        }
    }
    result
}

unsafe fn command_frequency() -> HashMap<String, (u32, usize)> {
    let mut result = HashMap::new();
    let list = unsafe { ffi::history_list() };
    if list.is_null() {
        return result;
    }
    let count = usize::try_from(unsafe { ffi::history_length }.max(0)).unwrap_or(0);
    let start = count.saturating_sub(MAX_HISTORY_ITEMS);
    let mut inspected_bytes = 0_usize;
    for (recency, index) in (start..count).rev().enumerate() {
        let entry = unsafe { *list.add(index) };
        if entry.is_null() {
            continue;
        }
        let line = unsafe { (*entry).line };
        if !line.is_null() {
            let line = unsafe { CStr::from_ptr(line) };
            if line.to_bytes().len() > MAX_SCALAR_BYTES
                || inspected_bytes.saturating_add(line.to_bytes().len()) > MAX_HISTORY_BYTES
            {
                break;
            }
            inspected_bytes = inspected_bytes.saturating_add(line.to_bytes().len());
            let line = line.to_string_lossy();
            if let Some(command) = first_command_word(&line) {
                let item = result.entry(command.to_owned()).or_insert((0_u32, 0_usize));
                item.0 = item.0.saturating_add(1);
                item.1 = item.1.max(MAX_HISTORY_ITEMS.saturating_sub(recency));
            }
        }
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
