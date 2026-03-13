
use crate::{
    db::Severity,
    tui::{app_state::AppState, layout::DashboardLayout, theme},
};
use chrono::Utc;
use ratatui::{
    layout::Constraint,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, layout::Rect,
};

pub fn render(f: &mut Frame, area: Rect, state: &AppState) {
    let lo = DashboardLayout::compute(area);
    render_overview(f, lo.stats, state);
    render_jobs(f, lo.jobs, state);
    render_findings(f, lo.findings, state);
    render_chart(f, lo.chart, state);
    render_activity(f, lo.activity, state);
}

fn render_activity(f: &mut Frame, area: Rect, state: &AppState) {
    use ratatui::widgets::Sparkline;
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ ACTIVITY ", theme::style_title())),
        )
        .data(&state.activity_log)
        .style(theme::style_accent());
    f.render_widget(sparkline, area);
}

fn render_overview(f: &mut Frame, area: Rect, state: &AppState) {
    let crit_count = state.findings.iter().filter(|fi| fi.severity == Severity::Critical).count();
    let high_count = state.findings.iter().filter(|fi| fi.severity == Severity::High).count();
    let med_count  = state.findings.iter().filter(|fi| fi.severity == Severity::Medium).count();
    let low_count  = state.findings.iter().filter(|fi| fi.severity == Severity::Low).count();
    let info_count = state.findings.iter().filter(|fi| fi.severity == Severity::Info).count();
    let running    = state.jobs.iter().filter(|j| !j.finished).count();
    let finished   = state.jobs.iter().filter(|j|  j.finished).count();

    let target_display = if state.current_target.is_empty() {
        "— not set —".to_string()
    } else {
        state.current_target.clone()
    };

    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled("  PROJECT ", theme::style_dim()),
            Span::styled(&state.cfg.general.project_name, theme::style_neon_pink()),
        ]),
        Line::from(vec![
            Span::styled("  TARGET  ", theme::style_dim()),
            Span::styled(target_display, if state.current_target.is_empty() { theme::style_dim() } else { theme::style_warning() }),
        ]),
        Line::from(Span::styled("  ─────────────────────────", theme::style_dim())),
        Line::raw(""),
        Line::from(Span::styled("  ASSETS", theme::style_accent())),
        Line::from(vec![
            Span::styled("  ◆ HOSTS       ", theme::style_dim()),
            Span::styled(state.db_stats.hosts.to_string(), theme::style_title()),
        ]),
        Line::from(vec![
            Span::styled("  ◆ PORTS       ", theme::style_dim()),
            Span::styled(state.db_stats.ports.to_string(), theme::style_accent()),
        ]),
        Line::raw(""),
        Line::from(Span::styled("  FINDINGS", theme::style_accent())),
        Line::from(vec![
            Span::styled("  ◆ TOTAL       ", theme::style_dim()),
            Span::styled(state.db_stats.findings.to_string(), theme::style_normal()),
        ]),
    ];

    if crit_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("    CRITICAL    ", theme::style_dim()),
            Span::styled(crit_count.to_string(), theme::style_critical()),
        ]));
    }
    if high_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("    HIGH        ", theme::style_dim()),
            Span::styled(high_count.to_string(), theme::style_high()),
        ]));
    }
    if med_count > 0 || low_count > 0 || info_count > 0 {
        lines.push(Line::from(vec![
            Span::styled("    MED/LOW/INF  ", theme::style_dim()),
            Span::styled(format!("{}/{}/{}", med_count, low_count, info_count), theme::style_dim()),
        ]));
    }

    lines.extend([
        Line::raw(""),
        Line::from(Span::styled("  JOBS", theme::style_accent())),
        Line::from(vec![
            Span::styled("  ◆ RUNNING     ", theme::style_dim()),
            Span::styled(running.to_string(), if running > 0 { theme::style_success() } else { theme::style_dim() }),
        ]),
        Line::from(vec![
            Span::styled("  ◆ FINISHED    ", theme::style_dim()),
            Span::styled(finished.to_string(), theme::style_dim()),
        ]),
        Line::raw(""),
        Line::from(Span::styled("  ─────────────────────────", theme::style_dim())),
        Line::from(vec![
            Span::styled("  TIME    ", theme::style_dim()),
            Span::styled(Utc::now().format("%H:%M:%S  UTC").to_string(), theme::style_dim()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  [w]", theme::style_keybind()),
            Span::styled(" Workflows     ", theme::style_dim()),
        ]),
        Line::from(vec![
            Span::styled("  [S]", theme::style_keybind()),
            Span::styled(" Stealth ops   ", theme::style_dim()),
        ]),
        Line::from(vec![
            Span::styled("  [^e]", theme::style_keybind()),
            Span::styled(" Export report", theme::style_dim()),
        ]),
        Line::from(vec![
            Span::styled("  [t]", theme::style_keybind()),
            Span::styled(" Set target    ", theme::style_dim()),
        ]),
    ]);
    
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("  INTELLIGENCE", theme::style_accent())));
    
    for sugg in state.intelligence_suggestions().iter().take(4) {
        lines.push(Line::from(vec![
            Span::styled("  ", theme::style_dim()),
            Span::styled(sugg, theme::style_normal()),
        ]));
    }

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(" ◆ SESSION OVERVIEW ", theme::style_title())),
        )
        .style(theme::style_panel());
    f.render_widget(para, area);
}

fn render_jobs(f: &mut Frame, area: Rect, state: &AppState) {
    let rows: Vec<Row> = state
        .jobs
        .iter()
        .rev()
        .take(80)
        .map(|job| {
            let (status_text, status_style) = if job.finished {
                match job.exit_code {
                    Some(0)  => (" DONE ✓ ", theme::style_success()),
                    Some(c)  => (if c == -1 { " KILLED " } else { " FAIL ✗ " }, theme::style_error()),
                    None     => (" DONE   ", theme::style_dim()),
                }
            } else {
                (" RUN ▶  ", theme::style_accent().add_modifier(Modifier::BOLD))
            };
            let elapsed = {
                let s = Utc::now().signed_duration_since(job.started).num_seconds();
                if s < 60 { format!("{}s", s) }
                else if s < 3600 { format!("{}m{}s", s/60, s%60) }
                else { format!("{}h{}m", s/3600, (s%3600)/60) }
            };
            let out_count = job.output.len();
            let progress_pct = (job.progress * 100.0) as u32;
            let bar_len = 10;
            let filled = (job.progress * bar_len as f64) as usize;
            let bar = format!("[{}{}] {}%", "█".repeat(filled), " ".repeat(bar_len - filled), progress_pct);
            
            Row::new(vec![
                Cell::from(job.id[..8.min(job.id.len())].to_string()).style(theme::style_dim()),
                Cell::from(Span::styled(&job.tool, theme::style_accent())),
                Cell::from(job.target[..20.min(job.target.len())].to_string()).style(theme::style_normal()),
                Cell::from(Span::styled(status_text, status_style)),
                Cell::from(Span::styled(bar, if job.finished { theme::style_dim() } else { theme::style_accent() })),
                Cell::from(elapsed).style(theme::style_dim()),
                Cell::from(format!("{}L", out_count)).style(theme::style_dim()),
            ])
        })
        .collect();

    let title = format!(
        " ◆ JOBS ({} running, {} total) ",
        state.jobs.iter().filter(|j| !j.finished).count(),
        state.jobs.len()
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(15),
            Constraint::Min(10),
            Constraint::Length(9),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Length(6),
        ],
    )
    .header(
        Row::new(vec!["ID", "TOOL", "TARGET", "STATUS", "PROGRESS", "ELAPSED", "LINES"])
            .style(theme::style_title().add_modifier(Modifier::UNDERLINED)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_set(theme::BORDER_SET)
            .border_style(theme::style_border_normal())
            .title(Span::styled(title, theme::style_title())),
    )
    .highlight_style(theme::style_selected())
    .highlight_symbol("▶ ")
    .style(theme::style_panel());
    let sel = state.selected_job.map(|i| {
        let n = state.jobs.len();
        if n == 0 { 0 } else { n.saturating_sub(1).saturating_sub(i) }
    });
    let mut ts = TableState::default().with_selected(sel);
    f.render_stateful_widget(table, area, &mut ts);
}

fn render_findings(f: &mut Frame, area: Rect, state: &AppState) {
    let visible_findings: Vec<_> = if state.search_active && !state.search_query.is_empty() {
        let q = state.search_query.to_lowercase();
        state.findings.iter()
            .filter(|fi| fi.title.to_lowercase().contains(&q) || fi.tool.to_lowercase().contains(&q))
            .take(200)
            .collect()
    } else {
        state.findings.iter().take(200).collect()
    };

    let items: Vec<ListItem> = visible_findings
        .iter()
        .map(|fi| {
            let sev_color = theme::severity_color(fi.severity.as_str());
            let sev_style = Style::default().fg(sev_color).add_modifier(Modifier::BOLD);
            let title_len = fi.title.len().min(38);
            ListItem::new(Line::from(vec![
                Span::styled(format!("[{:<5}]", &fi.severity.as_str().to_uppercase()[..4.min(fi.severity.as_str().len())]), sev_style),
                Span::raw(" "),
                Span::styled(fi.title[..title_len].to_string(), theme::style_normal()),
                Span::styled(format!("  ·{}", fi.tool), theme::style_dim()),
            ]))
        })
        .collect();

    let search_suffix = if state.search_active && !state.search_query.is_empty() {
        format!(" [search: {}]", state.search_query)
    } else { String::new() };

    let title = format!(
        " ◆ FINDINGS ({}){} ",
        state.db_stats.findings,
        search_suffix,
    );

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(title, theme::style_title())),
        )
        .style(theme::style_panel())
        .highlight_style(theme::style_selected())
        .highlight_symbol("▶ ");

    let mut ls = ListState::default().with_selected(state.selected_finding);
    f.render_stateful_widget(list, area, &mut ls);
}

fn render_chart(f: &mut Frame, area: Rect, state: &AppState) {
    let data: Vec<(&str, u64)> = vec![
        ("CRIT", state.findings.iter().filter(|fi| fi.severity == Severity::Critical).count() as u64),
        ("HIGH", state.findings.iter().filter(|fi| fi.severity == Severity::High).count() as u64),
        ("MED",  state.findings.iter().filter(|fi| fi.severity == Severity::Medium).count() as u64),
        ("LOW",  state.findings.iter().filter(|fi| fi.severity == Severity::Low).count() as u64),
        ("INFO", state.findings.iter().filter(|fi| fi.severity == Severity::Info).count() as u64),
    ];

    let max = data.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1);

    let chart = BarChart::default()
        .bar_width(4)
        .bar_gap(1)
        .bar_style(theme::style_accent())
        .value_style(theme::style_title())
        .label_style(theme::style_dim())
        .data(&data)
        .max(max)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_normal())
                .title(Span::styled(" ◆ SEVERITY ", theme::style_title())),
        );
    f.render_widget(chart, area);
}
