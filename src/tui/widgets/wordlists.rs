
use crate::tui::{app_state::AppState, theme};
use ratatui::{
    layout::{Constraint, Rect},
    style::Modifier,
    text::Span,
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};
use std::path::PathBuf;

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {

    let common_paths = vec![
        "/usr/share/wordlists",
        "/usr/share/seclists",
        "/usr/share/dirb/wordlists",
        "/usr/share/dirbuster/wordlists",
    ];

    let mut items = Vec::new();
    for path in common_paths {
        items.push(ListItem::new(Span::styled(format!("📂 {}", path), theme::style_accent())));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten().take(50) {
                let name = entry.file_name().to_string_lossy().into_owned();
                items.push(ListItem::new(format!("  📄 {}", name)));
            }
        }
    }

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(" ◆ WORDLIST EXPLORER ", theme::style_title())),
        )
        .style(theme::style_panel())
        .highlight_style(theme::style_selected())
        .highlight_symbol("▶ ");

    f.render_widget(list, area);
}
