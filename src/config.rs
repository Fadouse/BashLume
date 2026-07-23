use std::ffi::{CStr, CString};

use crate::ffi;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticsMode {
    Off,
    Marker,
    Inline,
}

#[derive(Clone, Debug)]
pub struct Theme {
    pub normal: String,
    pub command: String,
    pub builtin: String,
    pub unknown_command: String,
    pub keyword: String,
    pub string: String,
    pub variable: String,
    pub comment: String,
    pub operator: String,
    pub redirect: String,
    pub option: String,
    pub number: String,
    pub path: String,
    pub error: String,
    pub ghost: String,
    pub menu_selected: String,
    pub menu_meta: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub enabled: bool,
    pub colors_enabled: bool,
    pub diagnostics: DiagnosticsMode,
    pub diagnostic_delay_ms: u64,
    pub cache_limit_bytes: usize,
    pub max_candidates: usize,
    pub menu_rows: usize,
    pub theme: Theme,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            colors_enabled: true,
            diagnostics: DiagnosticsMode::Marker,
            diagnostic_delay_ms: 300,
            cache_limit_bytes: 16 * 1024 * 1024,
            max_candidates: 4096,
            menu_rows: 10,
            theme: Theme {
                normal: "0".into(),
                command: "38;5;114".into(),
                builtin: "1;38;5;108".into(),
                unknown_command: "4;38;5;203".into(),
                keyword: "1;38;5;175".into(),
                string: "38;5;222".into(),
                variable: "38;5;117".into(),
                comment: "2;38;5;244".into(),
                operator: "1;38;5;109".into(),
                redirect: "38;5;208".into(),
                option: "38;5;180".into(),
                number: "38;5;141".into(),
                path: "4;38;5;110".into(),
                error: "4;38;5;203".into(),
                ghost: "2;38;5;244".into(),
                menu_selected: "1;7".into(),
                menu_meta: "2;38;5;244".into(),
            },
        }
    }
}

impl Config {
    /// Reads ordinary (not necessarily exported) Bash variables once.
    ///
    /// # Safety
    /// Must run on Bash's main thread while Bash is not mutating variables.
    pub unsafe fn from_bash() -> Self {
        let mut config = Self::default();

        if let Some(value) = unsafe { shell_var("BASHLUME_ENABLED") } {
            config.enabled = parse_bool(&value, true);
        }
        let no_color = unsafe { shell_var("NO_COLOR") }.is_some()
            || unsafe { shell_var("BASHLUME_NO_COLOR") }
                .is_some_and(|value| parse_bool(&value, true));
        config.colors_enabled = !no_color;

        if let Some(value) = unsafe { shell_var("BASHLUME_DIAGNOSTICS") } {
            config.diagnostics = match value.to_ascii_lowercase().as_str() {
                "off" | "none" | "0" => DiagnosticsMode::Off,
                "inline" | "full" | "2" => DiagnosticsMode::Inline,
                _ => DiagnosticsMode::Marker,
            };
        }
        if let Some(value) = unsafe { shell_var("BASHLUME_DIAGNOSTIC_DELAY_MS") } {
            config.diagnostic_delay_ms = parse_bounded(&value, 50, 5000)
                .map(|value| value as u64)
                .unwrap_or(config.diagnostic_delay_ms);
        }
        if let Some(value) = unsafe { shell_var("BASHLUME_CACHE_MIB") } {
            let mib = parse_bounded(&value, 1, 1024).unwrap_or(16);
            config.cache_limit_bytes = mib.saturating_mul(1024 * 1024);
        }
        if let Some(value) = unsafe { shell_var("BASHLUME_MAX_CANDIDATES") } {
            config.max_candidates =
                parse_bounded(&value, 16, 65_536).unwrap_or(config.max_candidates);
        }
        if let Some(value) = unsafe { shell_var("BASHLUME_MENU_ROWS") } {
            config.menu_rows = parse_bounded(&value, 1, 100).unwrap_or(config.menu_rows);
        }

        macro_rules! color {
            ($field:ident, $name:literal) => {
                if let Some(value) = unsafe { shell_var($name) }.and_then(valid_sgr) {
                    config.theme.$field = value;
                }
            };
        }

        color!(normal, "BASHLUME_COLOR_NORMAL");
        color!(command, "BASHLUME_COLOR_COMMAND");
        color!(builtin, "BASHLUME_COLOR_BUILTIN");
        color!(unknown_command, "BASHLUME_COLOR_UNKNOWN_COMMAND");
        color!(keyword, "BASHLUME_COLOR_KEYWORD");
        color!(string, "BASHLUME_COLOR_STRING");
        color!(variable, "BASHLUME_COLOR_VARIABLE");
        color!(comment, "BASHLUME_COLOR_COMMENT");
        color!(operator, "BASHLUME_COLOR_OPERATOR");
        color!(redirect, "BASHLUME_COLOR_REDIRECT");
        color!(option, "BASHLUME_COLOR_OPTION");
        color!(number, "BASHLUME_COLOR_NUMBER");
        color!(path, "BASHLUME_COLOR_PATH");
        color!(error, "BASHLUME_COLOR_ERROR");
        color!(ghost, "BASHLUME_COLOR_GHOST");
        color!(menu_selected, "BASHLUME_COLOR_MENU_SELECTED");
        color!(menu_meta, "BASHLUME_COLOR_MENU_META");

        config
    }
}

fn parse_bool(value: &str, empty_value: bool) -> bool {
    if value.is_empty() {
        return empty_value;
    }
    !matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn parse_bounded(value: &str, min: usize, max: usize) -> Option<usize> {
    value.parse::<usize>().ok().map(|v| v.clamp(min, max))
}

fn valid_sgr(value: String) -> Option<String> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b';');
    valid.then_some(value)
}

/// # Safety
/// The returned string is copied before Bash can mutate the variable.
unsafe fn shell_var(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let variable = unsafe { ffi::find_variable(name.as_ptr()) };
    if variable.is_null() {
        return None;
    }
    let value = unsafe { (*variable).value };
    if value.is_null() {
        return Some(String::new());
    }
    Some(
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgr_rejects_terminal_escape_injection() {
        assert_eq!(
            valid_sgr("1;38;5;203".into()).as_deref(),
            Some("1;38;5;203")
        );
        assert!(valid_sgr("31m\\e]2;owned".into()).is_none());
    }

    #[test]
    fn bounds_numeric_configuration() {
        assert_eq!(parse_bounded("0", 1, 16), Some(1));
        assert_eq!(parse_bounded("999", 1, 16), Some(16));
        assert_eq!(parse_bounded("x", 1, 16), None);
    }
}
