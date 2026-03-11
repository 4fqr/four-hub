
use crate::tui::{app_state::AppState, theme};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Modifier,
    text::Span,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    render_output(f, chunks[0], state);
    render_input(f, chunks[1], state);
}

fn render_output(f: &mut Frame, area: Rect, state: &AppState) {
    let visible = (area.height as usize).saturating_sub(2);
    let lines: Vec<ListItem> = state
        .terminal
        .lines
        .iter()
        .rev()
        .take(visible)
        .rev()
        .map(|l| {
            let style = if l.starts_with("$ ") {
                theme::style_accent().add_modifier(Modifier::BOLD)
            } else if l.starts_with("ERROR") || l.starts_with("error") {
                theme::style_error()
            } else if l.starts_with("[stderr]") || l.starts_with("stderr:") {
                theme::style_error()
            } else if l.starts_with("✓") || l.starts_with("▶") || l.starts_with("[done]") {
                theme::style_success()
            } else if l.starts_with("[warn") || l.starts_with("WARNING") {
                theme::style_warning()
            } else {
                theme::style_normal()
            };
            ListItem::new(Span::styled(l.clone(), style))
        })
        .collect();
    let active_job = state.jobs.iter().rev().find(|j| !j.finished);
    let title = if let Some(job) = active_job {
        format!(" ◆ TERMINAL — running: {} ▶ {} ", job.tool, job.target)
    } else {
        " ◆ EMBEDDED TERMINAL ".to_string()
    };

    let list = List::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(if state.terminal.focused {
                    theme::style_border_focused()
                } else {
                    theme::style_border_normal()
                })
                .title(Span::styled(title, theme::style_title())),
        )
        .style(theme::style_panel());

    f.render_widget(list, area);
}

fn render_input(f: &mut Frame, area: Rect, state: &AppState) {
    let cursor = if state.terminal.focused { "█" } else { " " };
    let content = format!("$ {}{cursor}", state.terminal.input);
    let para = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(if state.terminal.focused {
                    theme::style_border_focused()
                } else {
                    theme::style_border_normal()
                })
                .title(Span::styled(" INPUT  [Esc] Blur ", theme::style_dim())),
        )
        .style(if state.terminal.focused {
            theme::style_accent()
        } else {
            theme::style_dim()
        });
    f.render_widget(para, area);
}
