
use crate::tui::{app_state::AppState, theme};
use ratatui::{
    layout::Rect,
    text::Span,
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state.wordlist_files.iter().enumerate().map(|(i, path)| {
        let name = std::path::Path::new(path).file_name().unwrap_or_default().to_string_lossy();
        let style = if Some(path.clone()) == state.active_wordlist {
            theme::style_success()
        } else if i == state.selected_wordlist {
            theme::style_selected()
        } else {
            theme::style_normal()
        };

        ListItem::new(Span::styled(format!("  📄 {}", name), style))
    }).collect();

    let mut list_state = ListState::default();
    list_state.select(Some(state.selected_wordlist));

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(" ◆ WORDLIST EXPLORER ", theme::style_title())),
        )
        .style(theme::style_panel());

    f.render_stateful_widget(list, area, &mut list_state);
}
