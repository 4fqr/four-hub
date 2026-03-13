
use crate::tui::{
    app_state::{AppState, Panel},
    layout::WorkspaceLayout,
    theme,
};
use ratatui::{
    layout::{Constraint, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let main_lo = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([ratatui::layout::Constraint::Length(3), ratatui::layout::Constraint::Min(0)])
        .split(area);
    
    render_summary(f, main_lo[0], state);
    
    let lo = WorkspaceLayout::compute(main_lo[1]);
    render_hosts(f, lo.hosts, state);
    render_ports(f, lo.ports, state);
    render_findings(f, lo.findings, state);
}

fn render_summary(f: &mut Frame, area: Rect, state: &AppState) {
    let crit = state.findings.iter().filter(|fi| fi.severity == crate::db::Severity::Critical).count();
    let high = state.findings.iter().filter(|fi| fi.severity == crate::db::Severity::High).count();
    let med  = state.findings.iter().filter(|fi| fi.severity == crate::db::Severity::Medium).count();
    
    let content = vec![
        Line::from(vec![
            Span::styled(" ◆ TACTICAL OVERVIEW ", theme::style_title()),
            Span::raw("  "),
            Span::styled(format!("🔥 CRITICAL: {}", crit), if crit > 0 { theme::style_critical() } else { theme::style_dim() }),
            Span::raw("  "),
            Span::styled(format!("⚠️ HIGH: {}", high), if high > 0 { theme::style_high() } else { theme::style_dim() }),
            Span::raw("  "),
            Span::styled(format!("🔸 MED: {}", med), theme::style_dim()),
            Span::raw("    "),
            Span::styled("TARGET: ", theme::style_dim()),
            Span::styled(&state.current_target, theme::style_accent()),
        ])
    ];
    
    let para = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).border_set(theme::BORDER_SET).border_style(theme::style_border_normal()))
        .style(theme::style_panel());
    f.render_widget(para, area);
}

fn render_hosts(f: &mut Frame, area: Rect, state: &AppState) {
    let focused = state.panel == Panel::Left;
    let border_style = if focused { theme::style_border_focused() } else { theme::style_border_normal() };

    let rows: Vec<Row> = state
        .hosts
        .iter()
        .map(|h| {
            Row::new(vec![
                Cell::from(h.address.chars().take(20).collect::<String>()),
                Cell::from(h.hostname.as_deref().unwrap_or("—").chars().take(20).collect::<String>()),
                Cell::from(h.os.as_deref().unwrap_or("—").chars().take(12).collect::<String>()),
            ])
        })
        .collect();

    let title = format!(" ◆ HOSTS ({}) ", state.hosts.len());

    let table = Table::new(
        rows,
        [Constraint::Min(15), Constraint::Min(15), Constraint::Length(13)],
    )
    .header(Row::new(vec!["IP / ADDRESS", "HOSTNAME", "OS"]).style(theme::style_title()))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(border_style)
            .title(Span::styled(title, theme::style_title())),
    )
    .highlight_style(theme::style_selected())
    .highlight_symbol(if focused { "▶ " } else { "  " })
    .style(theme::style_panel());

    let mut ts = TableState::default().with_selected(state.selected_host);
    f.render_stateful_widget(table, area, &mut ts);
}

fn render_ports(f: &mut Frame, area: Rect, state: &AppState) {
    let focused = state.panel == Panel::Top;
    let border_style = if focused { theme::style_border_focused() } else { theme::style_border_normal() };

    if state.selected_host.is_none() && state.ports.is_empty() {
        let para = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled("  ← Select a host to see its ports.", theme::style_dim())),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(border_style)
                .title(Span::styled(" ◆ PORTS ", theme::style_title())),
        )
        .style(theme::style_panel());
        f.render_widget(para, area);
        return;
    }

    let rows: Vec<Row> = state
        .ports
        .iter()
        .map(|p| {
            let state_style = if p.state == "open" { theme::style_success() } else { theme::style_error() };
            Row::new(vec![
                Cell::from(p.port.to_string()),
                Cell::from(p.protocol.clone()),
                Cell::from(Span::styled(p.state.clone(), state_style)),
                Cell::from(p.service.as_deref().unwrap_or("—").chars().take(12).collect::<String>()),
                Cell::from(p.version.as_deref().unwrap_or("—").chars().take(25).collect::<String>()),
            ])
        })
        .collect();

    let open_count = state.ports.iter().filter(|p| p.state == "open").count();
    let title = format!(" ◆ PORTS ({} open / {}) ", open_count, state.ports.len());

    let table = Table::new(
        rows,
        [Constraint::Length(6), Constraint::Length(6), Constraint::Length(9), Constraint::Length(13), Constraint::Min(10)],
    )
    .header(Row::new(vec!["PORT", "PROTO", "STATE", "SERVICE", "VERSION"]).style(theme::style_title()))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(border_style)
            .title(Span::styled(title, theme::style_title())),
    )
    .highlight_style(theme::style_selected())
    .highlight_symbol(if focused { "▶ " } else { "  " })
    .style(theme::style_panel());

    let mut ts = TableState::default().with_selected(state.selected_port);
    f.render_stateful_widget(table, area, &mut ts);
}

fn render_findings(f: &mut Frame, area: Rect, state: &AppState) {
    let focused = state.panel == Panel::Bottom;
    let border_style = if focused { theme::style_border_focused() } else { theme::style_border_normal() };

    let rows: Vec<Row> = state
        .findings
        .iter()
        .map(|fi| {
            let sev_style = ratatui::style::Style::default()
                .fg(theme::severity_color(fi.severity.as_str()));
            Row::new(vec![
                Cell::from(Span::styled(fi.severity.as_str().to_uppercase(), sev_style)),
                Cell::from(fi.tool.chars().take(10).collect::<String>()),
                Cell::from(fi.title.chars().take(45).collect::<String>()),
            ])
        })
        .collect();

    let title = format!(" ◆ FINDINGS ({}) ", state.findings.len());

    let table = Table::new(
        rows,
        [Constraint::Length(9), Constraint::Length(11), Constraint::Min(20)],
    )
    .header(Row::new(vec!["SEV", "TOOL", "TITLE"]).style(theme::style_title()))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(border_style)
            .title(Span::styled(title, theme::style_title())),
    )
    .highlight_style(theme::style_selected())
    .highlight_symbol(if focused { "▶ " } else { "  " })
    .style(theme::style_panel());

    let mut ts = TableState::default().with_selected(state.selected_finding);
    f.render_stateful_widget(table, area, &mut ts);
}
