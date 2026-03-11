// ─── Four-Hub · tui/widgets/launcher.rs ──────────────────────────────────────
//! Tool Launcher view: category tree on the left, tool list in the centre,
//! detail / argument panel at the bottom.

use crate::tui::{app_state::AppState, layout::LauncherLayout, theme};
use std::path::PathBuf;
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

fn tool_installed(binary: &str) -> bool {
    // Fast path: check PATH by looking for the binary in standard dirs.
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|mut p| { p.push(binary); p.is_file() })
        })
        .unwrap_or(false)
        || PathBuf::from(binary).is_file()   // absolute path
}

fn render_tools(f: &mut Frame, area: Rect, state: &AppState) {
    let total = state.tools_in_category.len();
    let installed_count = state.tools_in_category.iter()
        .filter(|s| tool_installed(&s.binary)).count();

    let items: Vec<ListItem> = state
        .tools_in_category
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let is_installed = tool_installed(&spec.binary);
            let selected = i == state.selected_tool;
            let name_style = if selected { theme::style_selected() } else { theme::style_normal() };
            let badge_style = if is_installed { theme::style_installed() } else { theme::style_missing() };
            let badge = if is_installed { " ✓" } else { " ✗" };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(&spec.name, name_style),
                Span::styled(badge, badge_style),
                Span::styled(
                    format!("  {}", spec.description.chars().take(36).collect::<String>()),
                    theme::style_dim(),
                ),
            ]))
        })
        .collect();

    let title = if total == 0 {
        " ◆ TOOLS (No tools – check tools.toml) ".to_string()
    } else {
        format!(" ◆ TOOLS ({}/{} installed) ", installed_count, total)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(title, theme::style_title())),
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
            let installed = tool_installed(&spec.binary);
            let inst_style = if installed { theme::style_installed() } else { theme::style_missing() };
            let inst_label = if installed { "✓ installed" } else { "✗ not in PATH" };
            let full_cmd = format!("{} {} {}", spec.binary, spec.default_args.join(" "), state.current_target);
            vec![
                Line::from(vec![
                    Span::styled("  NAME        ", theme::style_dim()),
                    Span::styled(&spec.name, theme::style_title()),
                ]),
                Line::from(vec![
                    Span::styled("  BINARY      ", theme::style_dim()),
                    Span::styled(&spec.binary, theme::style_accent()),
                    Span::raw("  "),
                    Span::styled(inst_label, inst_style),
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
                    Span::styled(
                        if state.current_target.is_empty() { "(not set — press t)" } else { &state.current_target },
                        if state.current_target.is_empty() { theme::style_dim() } else { theme::style_warning() },
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  FULL CMD    ", theme::style_dim()),
                    Span::styled(full_cmd.chars().take(60).collect::<String>(), theme::style_dim()),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  [r] ", theme::style_keybind()),
                    Span::styled("Run tool   ", theme::style_normal()),
                    Span::styled("[t] ", theme::style_keybind()),
                    Span::styled("Set target   ", theme::style_normal()),
                    Span::styled("[</> ] ", theme::style_keybind()),
                    Span::styled("Switch category", theme::style_normal()),
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
        "privesc"      => "⚡",
        "custom"       => "🛠",
        _              => "▸",
    }
}
