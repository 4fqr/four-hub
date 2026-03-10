// ─── Four-Hub · tui/widgets/launcher.rs ──────────────────────────────────────
//! Tool Launcher view: category tree on the left, tool list in the centre,
//! detail / argument panel at the bottom.

use crate::tui::{app_state::AppState, layout::LauncherLayout, theme};
use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let lo = LauncherLayout::compute(area);
    render_categories(f, lo.categories, state);
    render_tools(f, lo.tools, state);
    render_detail(f, lo.detail, state);
}

fn render_categories(f: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state
        .tool_categories
        .iter()
        .enumerate()
        .map(|(i, cat)| {
            let icon = category_icon(cat);
            let style = if i == state.selected_category {
                theme::style_selected()
            } else {
                theme::style_normal()
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!(" {icon} ")),
                Span::styled(cat, style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(" ◆ CATEGORIES ", theme::style_title())),
        )
        .style(theme::style_panel())
        .highlight_style(theme::style_selected());

    let mut ls = ListState::default().with_selected(Some(state.selected_category));
    f.render_stateful_widget(list, area, &mut ls);
}

fn render_tools(f: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state
        .tools_in_category
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let style = if i == state.selected_tool {
                theme::style_selected()
            } else {
                theme::style_normal()
            };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(&spec.name, style),
                Span::styled(
                    format!("  — {}", spec.description.chars().take(40).collect::<String>()),
                    theme::style_dim(),
                ),
            ]))
        })
        .collect();

    let suffix = if items.is_empty() {
        " (No tools – check tools.toml) "
    } else {
        ""
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(
                    format!(" ◆ TOOLS{suffix} "),
                    theme::style_title(),
                )),
        )
        .style(theme::style_panel())
        .highlight_style(theme::style_selected());

    let mut ls = ListState::default().with_selected(
        if state.tools_in_category.is_empty() { None } else { Some(state.selected_tool) },
    );
    f.render_stateful_widget(list, area, &mut ls);
}

fn render_detail(f: &mut Frame, area: Rect, state: &AppState) {
    let content = match state.selected_tool_spec() {
        None => vec![Line::from(Span::styled("  Select a tool above.", theme::style_dim()))],
        Some(spec) => {
            vec![
                Line::from(vec![
                    Span::styled("  NAME        ", theme::style_dim()),
                    Span::styled(&spec.name, theme::style_title()),
                ]),
                Line::from(vec![
                    Span::styled("  BINARY      ", theme::style_dim()),
                    Span::styled(&spec.binary, theme::style_accent()),
                ]),
                Line::from(vec![
                    Span::styled("  DESCRIPTION ", theme::style_dim()),
                    Span::styled(&spec.description, theme::style_normal()),
                ]),
                Line::from(vec![
                    Span::styled("  DEFAULT ARGS", theme::style_dim()),
                    Span::styled(spec.default_args.join(" "), theme::style_neon_pink()),
                ]),
                Line::from(vec![
                    Span::styled("  TARGET      ", theme::style_dim()),
                    Span::styled(&state.current_target, theme::style_warning()),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  [r] Run  ", theme::style_keybind()),
                    Span::styled("[t] Set Target  ", theme::style_keybind()),
                ]),
            ]
        }
    };

    let para = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ DETAIL ", theme::style_title())),
        )
        .style(theme::style_panel())
        .wrap(Wrap { trim: true });
    f.render_widget(para, area);
}

fn category_icon(cat: &str) -> &'static str {
    match cat.to_lowercase().as_str() {
        "recon"        => "🔭",
        "exploitation" => "💥",
        "web"          => "🌐",
        "wireless"     => "📡",
        "password"     => "🔑",
        "forensics"    => "🔬",
        "network"      => "🕸",
        "custom"       => "🛠",
        _              => "▸",
    }
}
