use std::ffi::CStr;

use unicode_width::UnicodeWidthChar;

use crate::completion::matcher::Candidate;
use crate::config::{Config, Theme};
use crate::ffi;
use crate::syntax::{Diagnostic, Style};

pub struct MenuView<'a> {
    pub candidates: &'a [Candidate],
    pub selected: usize,
    pub pending: bool,
    pub truncated: bool,
}

pub struct RenderModel<'a> {
    pub line: &'a str,
    pub point: usize,
    pub styles: &'a [Style],
    pub ghost: Option<&'a str>,
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
        let width = terminal_size().0.max(1) as usize;
        let prompt_column = unsafe { prompt_last_line_width(width) };
        let point = floor_char_boundary(model.line, model.point.min(model.line.len()));
        let cursor = displayed_position(&model.line[..point], prompt_column, width);

        let mut output = Vec::with_capacity(model.line.len().saturating_mul(2).saturating_add(512));
        output.extend_from_slice(b"\x1b7\r");
        if cursor.row > 0 {
            push_csi_number(&mut output, cursor.row, b'A');
        }
        if prompt_column > 0 {
            push_csi_number(&mut output, prompt_column, b'C');
        }
        // Remove the previous ghost/menu before repainting from input start.
        output.extend_from_slice(b"\x1b[0m\x1b[J");

        render_styled_line(
            &mut output,
            model.line,
            model.styles,
            prompt_column,
            width,
            &config.theme,
            config.colors_enabled,
        );

        if let Some(ghost) = model.ghost {
            push_sgr(&mut output, &config.theme.ghost);
            render_safe(&mut output, ghost, prompt_column, width);
            output.extend_from_slice(b"\x1b[0m");
        }

        if let Some(menu) = model.menu {
            render_menu(&mut output, menu, config, width);
        }
        if let Some(diagnostic) = model.diagnostic {
            output.extend_from_slice(b"\r\n");
            push_sgr(&mut output, &config.theme.error);
            render_safe(&mut output, &diagnostic.message, 0, width);
            output.extend_from_slice(b"\x1b[0m");
        }

        output.extend_from_slice(b"\x1b[J\x1b8");
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
        output.extend_from_slice(b"\x1b7\r");
        if cursor.row > 0 {
            push_csi_number(&mut output, cursor.row, b'A');
        }
        if prompt_column > 0 {
            push_csi_number(&mut output, prompt_column, b'C');
        }
        output.extend_from_slice(b"\x1b[0m\x1b[J");
        render_safe(&mut output, line, prompt_column, width);
        output.extend_from_slice(b"\x1b[0m\x1b[J\x1b8");
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
    theme: &Theme,
    colors_enabled: bool,
) {
    let mut current = Style::Normal;
    let mut column = start_column;
    if colors_enabled {
        push_sgr(output, sgr_for(current, theme));
    }
    for (index, character) in line.char_indices() {
        let style = styles.get(index).copied().unwrap_or(Style::Normal);
        if colors_enabled && style != current {
            current = style;
            push_sgr(output, sgr_for(style, theme));
        }
        render_character(output, character, &mut column, terminal_width);
    }
    output.extend_from_slice(b"\x1b[0m");
}

fn render_menu(output: &mut Vec<u8>, menu: MenuView<'_>, config: &Config, width: usize) {
    let rows = config.menu_rows.min(menu.candidates.len());
    if rows == 0 {
        if menu.pending {
            output.extend_from_slice(b"\r\n");
            push_sgr(output, &config.theme.menu_meta);
            output.extend_from_slice(b"  scanning\xe2\x80\xa6\x1b[0m");
        }
        return;
    }

    let start = if menu.selected >= rows {
        menu.selected + 1 - rows
    } else {
        0
    };
    for (offset, candidate) in menu.candidates.iter().skip(start).take(rows).enumerate() {
        let index = start + offset;
        output.extend_from_slice(b"\r\n");
        if index == menu.selected {
            push_sgr(output, &config.theme.menu_selected);
            output.extend_from_slice(b"> ");
        } else {
            output.extend_from_slice(b"  ");
        }
        let reserved = candidate.kind.label().len().saturating_add(5);
        render_truncated(
            output,
            &candidate.display,
            width.saturating_sub(reserved).max(4),
        );
        output.extend_from_slice(b"\x1b[0m ");
        push_sgr(output, &config.theme.menu_meta);
        output.push(b'[');
        output.extend_from_slice(candidate.kind.label().as_bytes());
        output.push(b']');
        output.extend_from_slice(b"\x1b[0m");
    }

    if menu.pending || menu.truncated || menu.candidates.len() > rows {
        output.extend_from_slice(b"\r\n");
        push_sgr(output, &config.theme.menu_meta);
        let mut metadata = format!("  {} candidates", menu.candidates.len());
        if menu.truncated {
            metadata.push_str(" (top results; truncated)");
        }
        if menu.pending {
            metadata.push_str(" (scanning\u{2026})");
        }
        render_truncated(output, &metadata, width.saturating_sub(2));
        output.extend_from_slice(b"\x1b[0m");
    }
}

fn render_truncated(output: &mut Vec<u8>, text: &str, limit: usize) {
    let mut used = 0_usize;
    for character in text.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used.saturating_add(character_width) > limit {
            output.extend_from_slice("…".as_bytes());
            break;
        }
        let mut column = used;
        render_character(output, character, &mut column, usize::MAX);
        used = used.saturating_add(character_width);
    }
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

#[derive(Clone, Copy)]
struct Position {
    row: usize,
    column: usize,
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
    fn prompt_parser_ignores_csi_and_osc_sequences() {
        assert_eq!(ansi_sequence_len(b"\x1b[38;5;2mrest"), 9);
        assert_eq!(ansi_sequence_len(b"\x1b]0;title\x07rest"), 10);
    }
}
