// ─── Four-Hub · tui/widgets/dashboard.rs ─────────────────────────────────────
//! Dashboard view: live stats, running jobs, recent findings, sparkline chart.

use crate::tui::{
    app_state::AppState,
    layout::DashboardLayout,
    theme,
};
use chrono::Utc;
use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{
        BarChart, Block, Borders, Cell, List, ListItem, ListState,
        Paragraph, Row, Table,
    },
    Frame,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let lo = DashboardLayout::compute(area);
    render_stats_panel(f, lo.stats, state);
    render_jobs_panel(f, lo.jobs, state);
    render_findings_panel(f, lo.findings, state);
    render_chart_panel(f, lo.chart, state);
}

// ── Stats panel ───────────────────────────────────────────────────────────────

fn render_stats_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ◆ HOSTS      ", theme::style_dim()),
            Span::styled(state.db_stats.hosts.to_string(), theme::style_title()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ◆ PORTS      ", theme::style_dim()),
            Span::styled(state.db_stats.ports.to_string(), theme::style_accent()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ◆ FINDINGS   ", theme::style_dim()),
            Span::styled(state.db_stats.findings.to_string(),
                if state.db_stats.findings > 0 { theme::style_warning() } else { theme::style_dim() }),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ◆ JOBS       ", theme::style_dim()),
            Span::styled(state.db_stats.jobs.to_string(), theme::style_accent()),
        ]),
        Line::raw(""),
        Line::from(Span::styled("  ─────────────────", theme::style_dim())),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  PROJECT ", theme::style_dim()),
            Span::styled(&state.cfg.general.project_name, theme::style_neon_pink()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ACTIVE  ", theme::style_dim()),
            Span::styled(
                state.jobs.iter().filter(|j| !j.finished).count().to_string(),
                theme::style_success(),
            ),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  TIME    ", theme::style_dim()),
            Span::styled(
                Utc::now().format("%H:%M:%S UTC").to_string(),
                theme::style_dim(),
            ),
        ]),
    ];

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ STATS ", theme::style_title())),
        )
        .style(theme::style_panel());
    f.render_widget(para, area);
}

// ── Jobs panel ────────────────────────────────────────────────────────────────

fn render_jobs_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let rows: Vec<Row> = state
        .jobs
        .iter()
        .rev()
        .take(50)
        .map(|job| {
            let status_span = if job.finished {
                match job.exit_code {
                    Some(0) => Span::styled("DONE  ", theme::style_success()),
                    Some(_) => Span::styled("FAIL  ", theme::style_error()),
                    None    => Span::styled("DONE  ", theme::style_dim()),
                }
            } else {
                Span::styled("RUN ▶ ", theme::style_accent())
            };
            let elapsed = Utc::now()
                .signed_duration_since(job.started)
                .num_seconds();
            Row::new(vec![
                Cell::from(job.id.chars().take(8).collect::<String>()),
                Cell::from(job.tool.clone()),
                Cell::from(job.target.chars().take(20).collect::<String>()),
                Cell::from(status_span),
                Cell::from(format!("{}s", elapsed)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            ratatui::layout::Constraint::Length(9),
            ratatui::layout::Constraint::Length(16),
            ratatui::layout::Constraint::Min(10),
            ratatui::layout::Constraint::Length(7),
            ratatui::layout::Constraint::Length(7),
        ],
    )
    .header(
        Row::new(vec!["ID", "TOOL", "TARGET", "STATUS", "TIME"])
            .style(theme::style_title()),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(theme::style_border_normal())
            .title(Span::styled(" ◆ RUNNING JOBS ", theme::style_title())),
    )
    .highlight_style(theme::style_selected())
    .style(theme::style_panel());

    let mut tbl_state = ratatui::widgets::TableState::default();
    f.render_stateful_widget(table, area, &mut tbl_state);
}

// ── Findings panel ────────────────────────────────────────────────────────────

fn render_findings_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state
        .findings
        .iter()
        .take(100)
        .map(|f| {
            let sev_style = Style::default().fg(theme::severity_color(f.severity.as_str()));
            ListItem::new(Line::from(vec![
                Span::styled(format!(" [{:<8}] ", f.severity.as_str()), sev_style),
                Span::styled(f.title.chars().take(40).collect::<String>(), theme::style_normal()),
                Span::styled(format!("  [{}]", f.tool), theme::style_dim()),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ RECENT FINDINGS ", theme::style_title())),
        )
        .style(theme::style_panel())
        .highlight_style(theme::style_selected());

    let mut ls = ListState::default();
    f.render_stateful_widget(list, area, &mut ls);
}

// ── Chart panel ───────────────────────────────────────────────────────────────

fn render_chart_panel(f: &mut Frame, area: Rect, state: &AppState) {
    // Build a severity breakdown bar chart.
    let counts: [(&str, u64); 5] = [
        ("CRIT", state.findings.iter().filter(|f| f.severity == crate::db::Severity::Critical).count() as u64),
        ("HIGH", state.findings.iter().filter(|f| f.severity == crate::db::Severity::High).count() as u64),
        ("MED",  state.findings.iter().filter(|f| f.severity == crate::db::Severity::Medium).count() as u64),
        ("LOW",  state.findings.iter().filter(|f| f.severity == crate::db::Severity::Low).count() as u64),
        ("INFO", state.findings.iter().filter(|f| f.severity == crate::db::Severity::Info).count() as u64),
    ];

    let bar_data: Vec<(&str, u64)> = counts.to_vec();

    let chart = BarChart::default()
        .bar_width(5)
        .bar_gap(1)
        .bar_style(theme::style_accent())
        .value_style(theme::style_title())
        .label_style(theme::style_dim())
        .data(&bar_data)
        .max(bar_data.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ SEVERITY ", theme::style_title())),
        );
    f.render_widget(chart, area);
}
