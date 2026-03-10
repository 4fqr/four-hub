// ─── Four-Hub · tui/widgets/inspector.rs ─────────────────────────────────────
//! Inspector view: detailed finding / host view with scrollable evidence pane.

use crate::tui::{app_state::AppState, layout::InspectorLayout, theme};
use ratatui::{
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    match &state.inspector_finding {
        None => render_placeholder(f, area),
        Some(finding) => {
            let lo = InspectorLayout::compute(area);
            render_header(f, lo.header, finding);
            render_body(f, lo.body, finding, state.inspector_scroll);
            render_evidence(f, lo.evidence, finding);
        }
    }
}

fn render_placeholder(f: &mut Frame, area: Rect) {
    let para = Paragraph::new(vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Select a finding in the Workspace view, then press [Enter].",
            theme::style_dim(),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(theme::style_border_normal())
            .title(Span::styled(" ◆ INSPECTOR ", theme::style_title())),
    )
    .style(theme::style_panel());
    f.render_widget(para, area);
}

fn render_header(f: &mut Frame, area: Rect, finding: &crate::db::Finding) {
    let sev_style = ratatui::style::Style::default()
        .fg(theme::severity_color(finding.severity.as_str()))
        .add_modifier(ratatui::style::Modifier::BOLD);

    let lines = vec![
        Line::from(vec![
            Span::styled("  TITLE     ", theme::style_dim()),
            Span::styled(&finding.title, theme::style_title()),
        ]),
        Line::from(vec![
            Span::styled("  SEVERITY  ", theme::style_dim()),
            Span::styled(finding.severity.as_str().to_uppercase(), sev_style),
            Span::raw("   "),
            Span::styled("TOOL ", theme::style_dim()),
            Span::styled(&finding.tool, theme::style_accent()),
        ]),
        Line::from(vec![
            Span::styled("  ID        ", theme::style_dim()),
            Span::styled(&finding.id, theme::style_dim()),
            Span::raw("   "),
            Span::styled(finding.created_at.format("%Y-%m-%d %H:%M UTC").to_string(), theme::style_dim()),
        ]),
    ];
    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(" ◆ FINDING DETAIL ", theme::style_title())),
        )
        .style(theme::style_panel());
    f.render_widget(para, area);
}

fn render_body(f: &mut Frame, area: Rect, finding: &crate::db::Finding, scroll: u16) {
    let para = Paragraph::new(finding.description.clone())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ DESCRIPTION ", theme::style_title())),
        )
        .style(theme::style_panel())
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(para, area);
}

fn render_evidence(f: &mut Frame, area: Rect, finding: &crate::db::Finding) {
    let content = finding
        .evidence
        .as_deref()
        .unwrap_or("No evidence attached.");
    let para = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ EVIDENCE ", theme::style_title())),
        )
        .style(theme::style_panel())
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}
