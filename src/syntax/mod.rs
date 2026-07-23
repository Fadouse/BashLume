use std::time::Instant;

use tree_sitter::{InputEdit, Node, Parser, Point, Tree};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Style {
    Normal = 0,
    Path = 10,
    Number = 20,
    Option = 25,
    Operator = 45,
    Redirect = 50,
    String = 55,
    Keyword = 60,
    Command = 65,
    Builtin = 66,
    Variable = 70,
    UnknownCommand = 85,
    Comment = 90,
    Error = 100,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandClass {
    Valid,
    Builtin,
    Unknown,
    Pending,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub message: String,
}

#[derive(Debug)]
pub struct HighlightResult {
    pub styles: Vec<Style>,
    pub diagnostic: Option<Diagnostic>,
    pub changed_at: Instant,
}

pub struct SyntaxEngine {
    parser: Parser,
    tree: Option<Tree>,
    previous: String,
    changed_at: Instant,
}

impl SyntaxEngine {
    pub fn new() -> Result<Self, tree_sitter::LanguageError> {
        let mut parser = Parser::new();
        let language = tree_sitter_bash::LANGUAGE.into();
        parser.set_language(&language)?;
        Ok(Self {
            parser,
            tree: None,
            previous: String::new(),
            changed_at: Instant::now(),
        })
    }

    pub fn highlight(
        &mut self,
        source: &str,
        mut classify_command: impl FnMut(&str) -> CommandClass,
    ) -> HighlightResult {
        if source != self.previous {
            self.changed_at = Instant::now();
        }

        // Keep pathological bracketed pastes bounded. Normal interactive lines
        // still use the complete incremental grammar.
        if source.len() > 256 * 1024 {
            self.previous.clear();
            self.previous.push_str(source);
            self.tree = None;
            return HighlightResult {
                styles: vec![Style::Normal; source.len()],
                diagnostic: None,
                changed_at: self.changed_at,
            };
        }

        if let Some(tree) = &mut self.tree {
            if source != self.previous {
                tree.edit(&edit_between(&self.previous, source));
            }
        }
        let parsed = self.parser.parse(source, self.tree.as_ref());
        self.tree = parsed;
        self.previous.clear();
        self.previous.push_str(source);

        let mut styles = vec![Style::Normal; source.len()];
        let mut diagnostic = None;
        if let Some(tree) = &self.tree {
            visit(
                tree.root_node(),
                source,
                &mut styles,
                &mut diagnostic,
                &mut classify_command,
            );
        }

        HighlightResult {
            styles,
            diagnostic,
            changed_at: self.changed_at,
        }
    }
}

fn visit(
    node: Node<'_>,
    source: &str,
    styles: &mut [Style],
    diagnostic: &mut Option<Diagnostic>,
    classify_command: &mut impl FnMut(&str) -> CommandClass,
) {
    let start = node.start_byte().min(styles.len());
    let end = node.end_byte().min(styles.len());
    let kind = node.kind();

    if node.is_error() && end > start {
        apply(styles, start, end, Style::Error);
        if diagnostic.is_none() {
            let token = source
                .get(start..end)
                .unwrap_or_default()
                .chars()
                .take(32)
                .collect::<String>();
            *diagnostic = Some(Diagnostic {
                message: if token.is_empty() {
                    "Bash syntax error".into()
                } else {
                    format!("Bash syntax error near `{token}`")
                },
            });
        }
    } else if let Some(style) = style_for_node(node, source, classify_command) {
        apply(styles, start, end, style);
    }

    // Tree-sitter represents a function's name as a plain `word`.
    if kind == "function_definition" {
        if let Some(name) = node.child_by_field_name("name") {
            apply(
                styles,
                name.start_byte().min(styles.len()),
                name.end_byte().min(styles.len()),
                Style::Command,
            );
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            visit(cursor.node(), source, styles, diagnostic, classify_command);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn style_for_node(
    node: Node<'_>,
    source: &str,
    classify_command: &mut impl FnMut(&str) -> CommandClass,
) -> Option<Style> {
    let kind = node.kind();
    match kind {
        "comment" => Some(Style::Comment),
        "string" | "raw_string" | "ansi_c_string" | "heredoc_body" | "heredoc_start" => {
            Some(Style::String)
        }
        "variable_name" | "simple_expansion" => Some(Style::Variable),
        "file_descriptor" | "number" => Some(Style::Number),
        "command_name" => {
            let text = source
                .get(node.start_byte()..node.end_byte())
                .unwrap_or_default();
            // Variable expansion and command substitution can resolve to a
            // valid command only when Bash executes the line. Never call them
            // unknown merely because their literal source is absent from PATH.
            let Some(command) = simple_unquote(text) else {
                return Some(Style::Command);
            };
            Some(match classify_command(&command) {
                CommandClass::Valid => Style::Command,
                CommandClass::Builtin => Style::Builtin,
                CommandClass::Unknown => Style::UnknownCommand,
                CommandClass::Pending => Style::Command,
            })
        }
        "redirect" | "heredoc_redirect" => Some(Style::Redirect),
        "word" => {
            let text = source
                .get(node.start_byte()..node.end_byte())
                .unwrap_or_default();
            if text.starts_with('-') && text.len() > 1 {
                Some(Style::Option)
            } else if text.contains('/') || text.starts_with('~') {
                Some(Style::Path)
            } else {
                None
            }
        }
        "if" | "then" | "elif" | "else" | "fi" | "for" | "while" | "until" | "do" | "done"
        | "case" | "in" | "esac" | "select" | "function" | "time" | "coproc" | "export"
        | "unset" => Some(Style::Keyword),
        "$" | "&&" | "||" | "|" | "&" | ";" | ";;" | ";&" | ";;&" | "!" | "(" | ")" | "{" | "}"
        | "[[" | "]]" | "((" | "))" => Some(Style::Operator),
        ">" | ">>" | "<" | "<<" | "<<<" | "<>" | ">&" | "<&" | ">|" | "&>" | "&>>" => {
            Some(Style::Redirect)
        }
        _ => None,
    }
}

fn apply(styles: &mut [Style], start: usize, end: usize, style: Style) {
    for current in styles.get_mut(start..end).into_iter().flatten() {
        if style >= *current {
            *current = style;
        }
    }
}

fn simple_unquote(text: &str) -> Option<String> {
    if text.contains(['$', '`']) {
        return None;
    }
    if text.len() >= 2
        && ((text.starts_with('\'') && text.ends_with('\''))
            || (text.starts_with('"') && text.ends_with('"')))
    {
        return Some(text[1..text.len() - 1].to_owned());
    }
    let mut output = String::with_capacity(text.len());
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            return None;
        } else {
            output.push(character);
        }
    }
    (!escaped).then_some(output)
}

fn edit_between(old: &str, new: &str) -> InputEdit {
    let mut start = old
        .bytes()
        .zip(new.bytes())
        .take_while(|(left, right)| left == right)
        .count();
    while start > 0 && (!old.is_char_boundary(start) || !new.is_char_boundary(start)) {
        start -= 1;
    }

    let mut common_suffix = old
        .len()
        .saturating_sub(start)
        .min(new.len().saturating_sub(start));
    while common_suffix > 0
        && old.as_bytes()[old.len() - common_suffix] != new.as_bytes()[new.len() - common_suffix]
    {
        common_suffix -= 1;
    }
    // The loop above only compares one byte after each decrement. Tighten with
    // a reverse scan to find the actual common suffix.
    common_suffix = old[start..]
        .bytes()
        .rev()
        .zip(new[start..].bytes().rev())
        .take_while(|(left, right)| left == right)
        .count();
    while common_suffix > 0
        && (!old.is_char_boundary(old.len() - common_suffix)
            || !new.is_char_boundary(new.len() - common_suffix))
    {
        common_suffix -= 1;
    }

    let old_end = old.len() - common_suffix;
    let new_end = new.len() - common_suffix;
    InputEdit {
        start_byte: start,
        old_end_byte: old_end,
        new_end_byte: new_end,
        start_position: point_at(old, start),
        old_end_position: point_at(old, old_end),
        new_end_position: point_at(new, new_end),
    }
}

fn point_at(source: &str, byte: usize) -> Point {
    let prefix = &source.as_bytes()[..byte.min(source.len())];
    let row = prefix.iter().filter(|&&item| item == b'\n').count();
    let column = prefix
        .iter()
        .rposition(|&item| item == b'\n')
        .map_or(prefix.len(), |position| prefix.len() - position - 1);
    Point::new(row, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_nested_bash_constructs_without_error() {
        let mut engine = SyntaxEngine::new().unwrap();
        let result = engine.highlight(
            "if [[ -n ${name:-} ]]; then echo \"$(printf %s \"$name\")\"; fi",
            |_| CommandClass::Valid,
        );
        assert!(result.diagnostic.is_none());
        assert!(result.styles.contains(&Style::Keyword));
        assert!(result.styles.contains(&Style::Variable));
        assert!(result.styles.contains(&Style::String));
    }

    #[test]
    fn definite_unexpected_token_is_reported() {
        let mut engine = SyntaxEngine::new().unwrap();
        let result = engine.highlight("echo )", |_| CommandClass::Valid);
        assert!(result.diagnostic.is_some());
        assert!(result.styles.contains(&Style::Error));
    }

    #[test]
    fn static_unknown_commands_are_errors_but_dynamic_commands_are_not() {
        let mut engine = SyntaxEngine::new().unwrap();
        let unknown = engine.highlight("whoim", |_| CommandClass::Unknown);
        assert!(unknown.styles.contains(&Style::UnknownCommand));

        let dynamic = engine.highlight("$command", |_| CommandClass::Unknown);
        assert!(!dynamic.styles.contains(&Style::UnknownCommand));
    }

    #[test]
    fn incomplete_construct_is_not_reported_as_a_nonempty_error() {
        let mut engine = SyntaxEngine::new().unwrap();
        let result = engine.highlight("if true; then", |_| CommandClass::Valid);
        assert!(result.diagnostic.is_none());
    }

    #[test]
    fn incremental_edit_tracks_multibyte_boundaries() {
        let old = "echo 测试";
        let new = "echo 测试值";
        let edit = edit_between(old, new);
        assert_eq!(edit.start_byte, old.len());
        assert_eq!(edit.old_end_byte, old.len());
        assert_eq!(edit.new_end_byte, new.len());
    }

    #[test]
    #[ignore = "development performance budget"]
    fn incremental_highlighting_stays_under_hot_path_budget() {
        let mut engine = SyntaxEngine::new().unwrap();
        let base = "printf '%s\\n' \"${value:-default}\" | sed -n '1p'; ".repeat(20);
        let mut samples = Vec::with_capacity(2_000);
        for iteration in 0..2_000 {
            let source = format!("{base}# {}", iteration & 1);
            let started = Instant::now();
            let result = engine.highlight(&source, |_| CommandClass::Valid);
            std::hint::black_box(result);
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p99 = samples[samples.len() * 99 / 100];
        eprintln!("syntax incremental p99: {p99:?} for {} bytes", base.len());
        if !cfg!(debug_assertions) {
            assert!(p99 < std::time::Duration::from_micros(500));
        }
    }
}
