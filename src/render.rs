use std::ffi::CStr;

use unicode_width::UnicodeWidthChar;

use crate::completion::matcher::Candidate;
use crate::config::{Config, HighlightMode, MenuDescriptionMode, Theme};
use crate::ffi;
use crate::syntax::{Diagnostic, Style};

pub struct MenuView<'a> {
    pub candidates: &'a [Candidate],
    pub selected: usize,
}

pub struct RenderModel<'a> {
    pub line: &'a str,
    pub point: usize,
    pub styles: &'a [Style],
    pub ghost: Option<&'a str>,
    pub error_marker: bool,
    pub menu: Option<MenuView<'a>>,
    pub diagnostic: Option<&'a Diagnostic>,
}

#[derive(Default)]
pub struct Renderer {
    overlay_visible: bool,
}

impl Renderer {
    /// Paints over Readline's normal output, then restores the cursor to the
    /// exact location Readline owns. Readline remains authoritative for all
    /// editing and cursor state.
    ///
    /// # Safety
    /// `rl_display_prompt` must point to a live NUL-terminated Readline prompt.
    pub unsafe fn draw(&mut self, model: RenderModel<'_>, config: &Config) {
        let (terminal_width, terminal_height) = terminal_size();
        let width = terminal_width.max(1) as usize;
        let height = terminal_height.max(2) as usize;
        let prompt_column = unsafe { prompt_last_line_width(width) };
        let point = floor_char_boundary(model.line, model.point.min(model.line.len()));
        let cursor = displayed_position(&model.line[..point], prompt_column, width);

        let mut output = Vec::with_capacity(model.line.len().saturating_mul(2).saturating_add(512));
        move_to_input_start(&mut output, cursor, prompt_column);
        // Remove the previous ghost/menu before repainting from input start.
        output.extend_from_slice(b"\x1b[0m\x1b[J");

        render_styled_line(
            &mut output,
            model.line,
            model.styles,
            prompt_column,
            width,
            config,
        );
        let mut end = displayed_position(model.line, prompt_column, width);

        if let Some(ghost) = model.ghost {
            push_sgr(&mut output, &config.theme.ghost);
            render_safe(&mut output, ghost, end.column, width);
            output.extend_from_slice(b"\x1b[0m");
            advance_text_position(&mut end, ghost, width);
        }

        if model.error_marker {
            push_sgr(&mut output, &config.theme.error);
            render_safe(&mut output, " \u{2717}", end.column, width);
            output.extend_from_slice(b"\x1b[0m");
            advance_text_position(&mut end, " \u{2717}", width);
        }

        if let Some(menu) = model.menu {
            let maximum_rows = config
                .menu_rows
                .min(height.saturating_sub(end.row.saturating_add(2)).max(1));
            let (added_rows, last_column) =
                render_menu(&mut output, menu, config, width, maximum_rows);
            if added_rows > 0 {
                end.row = end.row.saturating_add(added_rows);
                end.column = last_column;
            }
        }
        if let Some(diagnostic) = model.diagnostic {
            output.extend_from_slice(b"\r\n");
            push_sgr(&mut output, &config.theme.error);
            render_safe(&mut output, &diagnostic.message, 0, width);
            output.extend_from_slice(b"\x1b[0m");
            end.row = end.row.saturating_add(1);
            end.column = 0;
            advance_text_position(&mut end, &diagnostic.message, width);
        }

        output.extend_from_slice(b"\x1b[J");
        return_to_cursor(&mut output, end, cursor);
        write_terminal(&output);
        self.overlay_visible = true;
    }

    /// Clears ghost/menu output while preserving a plain copy of the line.
    /// Used immediately before Readline accepts the command.
    ///
    /// # Safety
    /// Same requirements as [`Self::draw`].
    pub unsafe fn clear_extras(&mut self, line: &str, point: usize) {
        if !self.overlay_visible {
            return;
        }
        let width = terminal_size().0.max(1) as usize;
        let prompt_column = unsafe { prompt_last_line_width(width) };
        let point = floor_char_boundary(line, point.min(line.len()));
        let cursor = displayed_position(&line[..point], prompt_column, width);
        let mut output = Vec::with_capacity(line.len() + 64);
        move_to_input_start(&mut output, cursor, prompt_column);
        output.extend_from_slice(b"\x1b[0m\x1b[J");
        render_safe(&mut output, line, prompt_column, width);
        let end = displayed_position(line, prompt_column, width);
        output.extend_from_slice(b"\x1b[0m\x1b[J");
        return_to_cursor(&mut output, end, cursor);
        write_terminal(&output);
        self.overlay_visible = false;
    }
}

fn render_styled_line(
    output: &mut Vec<u8>,
    line: &str,
    styles: &[Style],
    start_column: usize,
    terminal_width: usize,
    config: &Config,
) {
    let mut current = Style::Normal;
    let mut column = start_column;
    if config.colors_enabled {
        push_sgr(output, sgr_for(current, &config.theme));
    }
    for (index, character) in line.char_indices() {
        let parsed_style = styles.get(index).copied().unwrap_or(Style::Normal);
        let style = match config.highlight {
            HighlightMode::Full => parsed_style,
            HighlightMode::Errors if parsed_style == Style::Error => Style::Error,
            HighlightMode::Errors | HighlightMode::Off => Style::Normal,
        };
        if config.colors_enabled && style != current {
            current = style;
            push_sgr(output, sgr_for(style, &config.theme));
        }
        render_character(output, character, &mut column, terminal_width);
    }
    output.extend_from_slice(b"\x1b[0m");
}

fn render_menu(
    output: &mut Vec<u8>,
    menu: MenuView<'_>,
    config: &Config,
    width: usize,
    maximum_rows: usize,
) -> (usize, usize) {
    if menu.candidates.is_empty() {
        // Pending scans intentionally render no placeholder. The event hook
        // will repaint the completed candidates without a distracting flash.
        return (0, 0);
    }

    // Readline's default listing uses columns filled from top to bottom. Keep
    // one terminal column unused to avoid an autowrap at the right edge.
    let layout_width = width.saturating_sub(1).max(1);
    let selected_description = menu
        .candidates
        .get(menu.selected)
        .and_then(|candidate| candidate.description.as_deref())
        .filter(|description| !description.is_empty());
    let show_selected_description = config.menu_descriptions == MenuDescriptionMode::Selected
        && selected_description.is_some()
        && maximum_rows >= 2;
    let description_rows = usize::from(show_selected_description);
    let longest = menu
        .candidates
        .iter()
        .map(|candidate| candidate_menu_width(candidate, config.menu_descriptions))
        .max()
        .unwrap_or(1)
        .min(layout_width);
    let cell_width = longest.saturating_add(2).min(layout_width).max(1);
    let columns = (layout_width / cell_width).max(1);
    let rows_per_page = maximum_rows.saturating_sub(description_rows).max(1);
    let capacity = rows_per_page.saturating_mul(columns).max(1);
    let page_start = (menu.selected / capacity).saturating_mul(capacity);
    let page_end = page_start
        .saturating_add(capacity)
        .min(menu.candidates.len());
    let page_length = page_end.saturating_sub(page_start);
    let mut rows = page_length.div_ceil(columns).min(rows_per_page).max(1);
    let mut final_column = 0;

    for row in 0..rows {
        output.extend_from_slice(b"\r\n");
        let mut column = 0_usize;
        for display_column in 0..columns {
            let index = page_start
                .saturating_add(row)
                .saturating_add(display_column.saturating_mul(rows));
            if index >= page_end {
                break;
            }
            let candidate = &menu.candidates[index];
            let selected = index == menu.selected;
            let has_next = index.saturating_add(rows) < page_end;
            let text_limit = if has_next {
                cell_width.saturating_sub(2).max(1)
            } else {
                layout_width.saturating_sub(column).max(1)
            };
            let used = render_menu_candidate(
                output,
                candidate,
                selected,
                config,
                config.menu_descriptions == MenuDescriptionMode::Inline,
                text_limit,
            );
            output.extend_from_slice(b"\x1b[0m");
            column = column.saturating_add(used);
            if has_next {
                let padding = cell_width.saturating_sub(used);
                output.extend(std::iter::repeat_n(b' ', padding));
                column = column.saturating_add(padding);
            }
        }
        final_column = column;
    }

    if show_selected_description {
        output.extend_from_slice(b"\r\n");
        push_sgr(output, &config.theme.ghost);
        final_column = render_menu_text(
            output,
            selected_description.unwrap_or_default(),
            layout_width,
        );
        output.extend_from_slice(b"\x1b[0m");
        rows = rows.saturating_add(1);
    }

    (rows, final_column)
}

fn candidate_menu_width(candidate: &Candidate, mode: MenuDescriptionMode) -> usize {
    let display = menu_text_width(&candidate.display);
    if mode != MenuDescriptionMode::Inline {
        return display;
    }
    candidate
        .description
        .as_deref()
        .filter(|description| !description.is_empty())
        .map_or(display, |description| {
            display
                .saturating_add(2)
                .saturating_add(menu_text_width(description))
        })
}

fn render_menu_candidate(
    output: &mut Vec<u8>,
    candidate: &Candidate,
    selected: bool,
    config: &Config,
    inline_description: bool,
    limit: usize,
) -> usize {
    push_sgr(output, completion_sgr(candidate, config));
    if selected {
        push_sgr(output, &config.theme.menu_selected);
    }
    let mut used = render_menu_text(output, &candidate.display, limit);
    let description = inline_description
        .then_some(candidate.description.as_deref())
        .flatten()
        .filter(|description| !description.is_empty());
    if let Some(description) = description.filter(|_| used.saturating_add(2) < limit) {
        output.extend_from_slice(b"  ");
        used = used.saturating_add(2);
        push_sgr(output, &config.theme.ghost);
        if selected {
            push_sgr(output, &config.theme.menu_selected);
        }
        used = used.saturating_add(render_menu_text(
            output,
            description,
            limit.saturating_sub(used),
        ));
    }
    used
}

fn completion_sgr<'a>(candidate: &Candidate, config: &'a Config) -> &'a str {
    use crate::completion::matcher::CandidateKind;

    match candidate.kind {
        CandidateKind::Alias => &config.theme.keyword,
        CandidateKind::Function => &config.theme.variable,
        CandidateKind::Builtin => &config.theme.builtin,
        CandidateKind::Keyword => &config.theme.keyword,
        CandidateKind::Command | CandidateKind::Executable => &config.theme.completion_executable,
        CandidateKind::Option => &config.theme.option,
        CandidateKind::Subcommand => &config.theme.command,
        CandidateKind::Value => &config.theme.normal,
        CandidateKind::Directory => &config.theme.completion_directory,
        CandidateKind::File => config
            .theme
            .completion_extensions
            .iter()
            .find(|(suffix, _)| candidate.display.ends_with(suffix))
            .map_or(&config.theme.completion_file, |(_, color)| color),
        CandidateKind::Variable => &config.theme.variable,
        CandidateKind::User
        | CandidateKind::Group
        | CandidateKind::Host
        | CandidateKind::Service
        | CandidateKind::Signal
        | CandidateKind::Job => &config.theme.path,
    }
}

fn menu_text_width(text: &str) -> usize {
    text.chars().fold(0_usize, |width, character| {
        width.saturating_add(menu_character_width(character))
    })
}

fn menu_character_width(character: char) -> usize {
    match character {
        '\t' | '\n' | '\r' | '\u{7f}' => 2,
        character if character.is_control() && (character as u32) < 0x20 => 2,
        character if character.is_control() => 1,
        character => UnicodeWidthChar::width(character).unwrap_or(0),
    }
}

fn render_menu_text(output: &mut Vec<u8>, text: &str, limit: usize) -> usize {
    let mut used = 0_usize;
    for character in text.chars() {
        let character_width = menu_character_width(character);
        if used.saturating_add(character_width) > limit {
            if used < limit {
                output.extend_from_slice("…".as_bytes());
                used += 1;
            }
            break;
        }
        match character {
            '\t' => output.extend_from_slice(b"^I"),
            '\n' => output.extend_from_slice(b"^J"),
            '\r' => output.extend_from_slice(b"^M"),
            other => {
                let mut column = used;
                render_character(output, other, &mut column, usize::MAX);
            }
        }
        used = used.saturating_add(character_width);
    }
    used
}

fn render_safe(output: &mut Vec<u8>, text: &str, start_column: usize, width: usize) {
    let mut column = start_column;
    for character in text.chars() {
        render_character(output, character, &mut column, width);
    }
}

fn render_character(output: &mut Vec<u8>, character: char, column: &mut usize, width: usize) {
    match character {
        '\n' => {
            output.extend_from_slice(b"\r\n");
            *column = 0;
        }
        '\t' => {
            let spaces = 8 - (*column % 8);
            output.extend(std::iter::repeat_n(b' ', spaces));
            *column = advance_column(*column, spaces, width);
        }
        '\u{7f}' => {
            output.extend_from_slice(b"^?");
            *column = advance_column(*column, 2, width);
        }
        character if character.is_control() => {
            if (character as u32) < 0x20 {
                output.push(b'^');
                output.push((character as u8).saturating_add(0x40));
                *column = advance_column(*column, 2, width);
            } else {
                output.extend_from_slice("�".as_bytes());
                *column = advance_column(*column, 1, width);
            }
        }
        character => {
            let mut bytes = [0_u8; 4];
            output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
            *column = advance_column(*column, character_width, width);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Position {
    row: usize,
    column: usize,
}

fn move_to_input_start(output: &mut Vec<u8>, cursor: Position, prompt_column: usize) {
    output.push(b'\r');
    if cursor.row > 0 {
        push_csi_number(output, cursor.row, b'A');
    }
    if prompt_column > 0 {
        push_csi_number(output, prompt_column, b'C');
    }
}

fn return_to_cursor(output: &mut Vec<u8>, current: Position, cursor: Position) {
    output.push(b'\r');
    if current.row > cursor.row {
        push_csi_number(output, current.row - cursor.row, b'A');
    } else if cursor.row > current.row {
        push_csi_number(output, cursor.row - current.row, b'B');
    }
    if cursor.column > 0 {
        push_csi_number(output, cursor.column, b'C');
    }
}

fn advance_text_position(position: &mut Position, text: &str, width: usize) {
    let added = displayed_position(text, position.column, width);
    position.row = position.row.saturating_add(added.row);
    position.column = added.column;
}

fn displayed_position(text: &str, start_column: usize, width: usize) -> Position {
    let mut position = Position {
        row: 0,
        column: start_column,
    };
    for character in text.chars() {
        match character {
            '\n' => {
                position.row += 1;
                position.column = 0;
            }
            '\t' => {
                let amount = 8 - position.column % 8;
                advance_position(&mut position, amount, width);
            }
            character if character == '\u{7f}' || (character as u32) < 0x20 => {
                advance_position(&mut position, 2, width)
            }
            character if character.is_control() => advance_position(&mut position, 1, width),
            character => advance_position(
                &mut position,
                UnicodeWidthChar::width(character).unwrap_or(0),
                width,
            ),
        }
    }
    position
}

fn advance_position(position: &mut Position, amount: usize, width: usize) {
    let total = position.column.saturating_add(amount);
    position.row = position.row.saturating_add(total / width.max(1));
    position.column = total % width.max(1);
}

fn advance_column(column: usize, amount: usize, width: usize) -> usize {
    column.saturating_add(amount) % width.max(1)
}

unsafe fn prompt_last_line_width(terminal_width: usize) -> usize {
    let prompt = unsafe { ffi::rl_display_prompt };
    if prompt.is_null() {
        return 0;
    }
    let bytes = unsafe { CStr::from_ptr(prompt) }.to_bytes();
    let last_line = bytes.rsplit(|&byte| byte == b'\n').next().unwrap_or(bytes);
    let mut visible = Vec::with_capacity(last_line.len());
    let mut ignored = false;
    let mut index = 0_usize;
    while index < last_line.len() {
        match last_line[index] {
            0x01 => {
                ignored = true;
                index += 1;
            }
            0x02 => {
                ignored = false;
                index += 1;
            }
            0x1b if !ignored => {
                // Defensive fallback for prompts that forgot Readline's
                // \[...\] invisible markers.
                index += ansi_sequence_len(&last_line[index..]).max(1);
            }
            byte if !ignored => {
                visible.push(byte);
                index += 1;
            }
            _ => index += 1,
        }
    }
    let text = String::from_utf8_lossy(&visible);
    displayed_position(&text, 0, terminal_width).column
}

fn ansi_sequence_len(bytes: &[u8]) -> usize {
    if bytes.len() < 2 || bytes[0] != 0x1b {
        return 0;
    }
    match bytes[1] {
        b'[' => bytes
            .iter()
            .enumerate()
            .skip(2)
            .find(|(_, byte)| (0x40..=0x7e).contains(*byte))
            .map_or(bytes.len(), |(index, _)| index + 1),
        b']' => {
            for index in 2..bytes.len() {
                if bytes[index] == 0x07 {
                    return index + 1;
                }
                if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'\\') {
                    return index + 2;
                }
            }
            bytes.len()
        }
        _ => 2,
    }
}

fn sgr_for(style: Style, theme: &Theme) -> &str {
    match style {
        Style::Normal => &theme.normal,
        Style::Command => &theme.command,
        Style::Builtin => &theme.builtin,
        Style::UnknownCommand => &theme.unknown_command,
        Style::Keyword => &theme.keyword,
        Style::String => &theme.string,
        Style::Variable => &theme.variable,
        Style::Comment => &theme.comment,
        Style::Operator => &theme.operator,
        Style::Redirect => &theme.redirect,
        Style::Option => &theme.option,
        Style::Number => &theme.number,
        Style::Path => &theme.path,
        Style::Error => &theme.error,
    }
}

fn push_sgr(output: &mut Vec<u8>, sgr: &str) {
    output.extend_from_slice(b"\x1b[");
    output.extend_from_slice(sgr.as_bytes());
    output.push(b'm');
}

fn push_csi_number(output: &mut Vec<u8>, value: usize, suffix: u8) {
    output.extend_from_slice(b"\x1b[");
    output.extend_from_slice(value.to_string().as_bytes());
    output.push(suffix);
}

fn terminal_size() -> (u16, u16) {
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) };
    if result == 0 && size.ws_col > 0 {
        (size.ws_col, size.ws_row)
    } else {
        (80, 24)
    }
}

fn write_terminal(output: &[u8]) {
    let mut written = 0_usize;
    while written < output.len() {
        let result = unsafe {
            ffi::write(
                libc::STDERR_FILENO,
                output[written..].as_ptr().cast(),
                output.len() - written,
            )
        };
        if result <= 0 {
            break;
        }
        written += result as usize;
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::matcher::{CandidateKind, MatchClass};

    #[test]
    fn control_characters_are_never_emitted_as_terminal_commands() {
        let mut output = Vec::new();
        render_safe(&mut output, "a\u{1b}[31mb", 0, 80);
        assert_eq!(String::from_utf8(output).unwrap(), "a^[[31mb");
    }

    #[test]
    fn unicode_and_wrapping_positions_are_counted_visually() {
        let position = displayed_position("ab测试", 7, 10);
        assert_eq!(position.row, 1);
        assert_eq!(position.column, 3);
    }

    #[test]
    fn errors_only_mode_does_not_color_valid_syntax() {
        let config = Config::default();
        let mut output = Vec::new();
        render_styled_line(
            &mut output,
            "echo bad",
            &[Style::Command; 8],
            0,
            80,
            &config,
        );
        assert!(
            !output
                .windows(config.theme.command.len())
                .any(|window| window == config.theme.command.as_bytes())
        );

        output.clear();
        render_styled_line(&mut output, ")", &[Style::Error], 0, 80, &config);
        assert!(
            output
                .windows(config.theme.error.len())
                .any(|window| window == config.theme.error.as_bytes())
        );
    }

    #[test]
    fn completion_menu_uses_colored_readline_style_columns() {
        let candidates = ["who", "whoami"]
            .into_iter()
            .map(|display| Candidate {
                display: display.into(),
                value: display.into(),
                description: None,
                source_mask: 0,
                kind: CandidateKind::Command,
                append_space: true,
                score: 0,
                match_class: if display == "who" {
                    MatchClass::Exact
                } else {
                    MatchClass::Prefix
                },
            })
            .collect::<Vec<_>>();
        let config = Config::default();
        let mut output = Vec::new();
        let extent = render_menu(
            &mut output,
            MenuView {
                candidates: &candidates,
                selected: 0,
            },
            &config,
            80,
            10,
        );
        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(extent.0, 1);
        assert!(rendered.contains("who"));
        assert!(rendered.contains("whoami"));
        assert!(rendered.contains(&format!("\x1b[{}m", config.theme.completion_executable)));
        assert!(!rendered.contains("[command]"));
    }

    #[test]
    fn selected_description_uses_one_bounded_detail_row() {
        let candidates = vec![Candidate {
            display: "--branch".into(),
            value: "--branch".into(),
            description: Some("Select a Git branch".into()),
            source_mask: 1,
            kind: CandidateKind::Command,
            append_space: true,
            score: 0,
            match_class: MatchClass::Prefix,
        }];
        let config = Config::default();
        let mut output = Vec::new();
        let extent = render_menu(
            &mut output,
            MenuView {
                candidates: &candidates,
                selected: 0,
            },
            &config,
            24,
            4,
        );
        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(extent.0, 2);
        assert!(rendered.contains("--branch"));
        assert!(rendered.contains("Select a Git branch"));
    }

    #[test]
    fn inline_and_off_description_modes_are_respected() {
        let candidates = vec![Candidate {
            display: "--force".into(),
            value: "--force".into(),
            description: Some("Force the operation".into()),
            source_mask: 1,
            kind: CandidateKind::Command,
            append_space: true,
            score: 0,
            match_class: MatchClass::Prefix,
        }];
        let mut config = Config {
            menu_descriptions: MenuDescriptionMode::Inline,
            ..Config::default()
        };
        let mut output = Vec::new();
        let inline_extent = render_menu(
            &mut output,
            MenuView {
                candidates: &candidates,
                selected: 0,
            },
            &config,
            80,
            4,
        );
        assert_eq!(inline_extent.0, 1);
        assert!(String::from_utf8_lossy(&output).contains("Force the operation"));

        config.menu_descriptions = MenuDescriptionMode::Off;
        output.clear();
        render_menu(
            &mut output,
            MenuView {
                candidates: &candidates,
                selected: 0,
            },
            &config,
            80,
            4,
        );
        assert!(!String::from_utf8_lossy(&output).contains("Force the operation"));
    }

    #[test]
    fn cursor_return_is_relative_so_terminal_scrolling_is_safe() {
        let mut output = Vec::new();
        return_to_cursor(
            &mut output,
            Position { row: 11, column: 7 },
            Position { row: 2, column: 5 },
        );
        assert_eq!(output, b"\r\x1b[9A\x1b[5C");
        assert!(!output.windows(2).any(|window| window == b"\x1b7"));
    }

    #[test]
    fn menu_control_characters_cannot_create_rows() {
        let mut output = Vec::new();
        assert_eq!(render_menu_text(&mut output, "bad\nname", 20), 9);
        assert_eq!(String::from_utf8(output).unwrap(), "bad^Jname");
    }

    #[test]
    fn prompt_parser_ignores_csi_and_osc_sequences() {
        assert_eq!(ansi_sequence_len(b"\x1b[38;5;2mrest"), 9);
        assert_eq!(ansi_sequence_len(b"\x1b]0;title\x07rest"), 10);
    }
}
