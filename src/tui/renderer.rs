// ─── Four-Hub · tui/renderer.rs ──────────────────────────────────────────────
//! Sets up the raw-mode terminal and orchestrates per-frame rendering.

use crate::tui::{
    app_state::{ActiveView, AppState, NotifLevel, PopupKind},
    layout::{centre_rect, RootLayout},
    theme,
    widgets,
};
use anyhow::Result;
use crossterm::{
    cursor,
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{
    backend::CrosstermBackend,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use std::io::{self, Stdout};

pub struct Renderer {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Renderer {
    pub fn new() -> Result<Self> {
        let backend  = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Enter raw mode + alternate screen.
    pub fn enter(&mut self) -> Result<()> {
        enable_raw_mode()?;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            cursor::Hide,
        )?;
        self.terminal.clear()?;
        Ok(())
    }

    /// Leave raw mode + alternate screen.
    pub fn leave(&mut self) -> Result<()> {
        disable_raw_mode()?;
        execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            cursor::Show,
        )?;
        Ok(())
    }

    /// Render a single frame.
    pub fn draw(&mut self, state: &AppState) -> Result<()> {
        self.terminal.draw(|f| render_frame(f, state))?;
        Ok(())
    }
}

// ── Frame renderer ────────────────────────────────────────────────────────────

fn render_frame(f: &mut Frame, state: &AppState) {
    let root  = RootLayout::compute(f.size());

    render_statusbar(f, root.statusbar, state);
    render_helpbar(f, root.helpbar, state);
    render_notifbar(f, root.notifbar, state);

    match state.active_view {
        ActiveView::Dashboard    => widgets::dashboard::render(f, root.content, state),
        ActiveView::ToolLauncher => widgets::launcher::render(f, root.content, state),
        ActiveView::Workspace    => widgets::workspace::render(f, root.content, state),
        ActiveView::Inspector    => widgets::inspector::render(f, root.content, state),
        ActiveView::Terminal     => widgets::terminal::render(f, root.content, state),
    }

    // Overlay popups / modals on top.
    if let Some(popup) = &state.popup {
        let area = f.size();
        render_popup(f, area, popup, state);
    }
}

// ── Status bar ────────────────────────────────────────────────────────────────

fn render_statusbar(f: &mut Frame, area: Rect, state: &AppState) {
    let titles: Vec<Line> = [
        ActiveView::Dashboard,
        ActiveView::ToolLauncher,
        ActiveView::Workspace,
        ActiveView::Inspector,
        ActiveView::Terminal,
    ]
    .iter()
    .enumerate()
    .map(|(i, v)| {
        let key = format!("F{}", i + 1);
        Line::from(vec![
            Span::styled(format!("[{key}]"), theme::style_keybind()),
            Span::raw(" "),
            Span::styled(v.title(), if *v == state.active_view {
                theme::style_title()
            } else {
                theme::style_dim()
            }),
        ])
    })
    .collect();

    let selected = match state.active_view {
        ActiveView::Dashboard    => 0,
        ActiveView::ToolLauncher => 1,
        ActiveView::Workspace    => 2,
        ActiveView::Inspector    => 3,
        ActiveView::Terminal     => 4,
    };

    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(theme::BORDER_SET)
                .border_style(theme::style_border_focused())
                .title(Span::styled(
                    format!(
                        " ◆ FOUR-HUB v{}  ·  {}{}  ·  hosts:{}  findings:{} ",
                        env!("CARGO_PKG_VERSION"),
                        state.cfg.general.project_name,
                        if state.current_target.is_empty() { String::new() } else { format!("  ▶  {}", state.current_target) },
                        state.db_stats.hosts,
                        state.db_stats.findings,
                    ),
                    theme::style_title(),
                )),
        )
        .highlight_style(
            Style::default()
                .fg(theme::NEON_GREEN)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(Span::styled(" │ ", theme::style_dim()));

    f.render_widget(tabs, area);
}

// ── Help bar ──────────────────────────────────────────────────────────────────

fn render_helpbar(f: &mut Frame, area: Rect, state: &AppState) {
    let spans: Vec<Span> = match state.active_view {
        ActiveView::Dashboard => vec![
            Span::styled("[q]",   theme::style_keybind()), Span::raw(" Quit  "),
            Span::styled("[1-5]", theme::style_keybind()), Span::raw(" Views  "),
            Span::styled("[t]",   theme::style_keybind()), Span::raw(" Target  "),
            Span::styled("[w]",   theme::style_keybind()), Span::raw(" Workflows  "),
            Span::styled("[S]",   theme::style_keybind()), Span::raw(" Stealth  "),
            Span::styled("[^e]",  theme::style_keybind()), Span::raw(" Export  "),
            Span::styled("[^f]",  theme::style_keybind()), Span::raw(" Search  "),
            Span::styled("[?]",   theme::style_keybind()), Span::raw(" Help"),
        ],
        ActiveView::ToolLauncher => vec![
            Span::styled("[q]",    theme::style_keybind()), Span::raw(" Quit  "),
            Span::styled("[1-5]",  theme::style_keybind()), Span::raw(" Views  "),
            Span::styled("[↑/↓]",   theme::style_keybind()), Span::raw(" Tools  "),
            Span::styled("[</> ]", theme::style_keybind()), Span::raw(" Category  "),
            Span::styled("[r]",    theme::style_keybind()), Span::raw(" Run  "),
            Span::styled("[t]",    theme::style_keybind()), Span::raw(" Target  "),
            Span::styled("[?]",    theme::style_keybind()), Span::raw(" Help"),
        ],
        ActiveView::Workspace => vec![
            Span::styled("[q]",     theme::style_keybind()), Span::raw(" Quit  "),
            Span::styled("[1-5]",   theme::style_keybind()), Span::raw(" Views  "),
            Span::styled("[Tab]",   theme::style_keybind()), Span::raw(" Focus panel  "),
            Span::styled("[↑/↓]",    theme::style_keybind()), Span::raw(" Navigate  "),
            Span::styled("[Enter]", theme::style_keybind()), Span::raw(" Inspect  "),
            Span::styled("[d]",     theme::style_keybind()), Span::raw(" Delete  "),
            Span::styled("[?]",     theme::style_keybind()), Span::raw(" Help"),
        ],
        ActiveView::Inspector => vec![
            Span::styled("[q]",   theme::style_keybind()), Span::raw(" Quit  "),
            Span::styled("[1-5]", theme::style_keybind()), Span::raw(" Views  "),
            Span::styled("[↑/↓]", theme::style_keybind()), Span::raw(" Scroll  "),
            Span::styled("[PgU/PgD]", theme::style_keybind()), Span::raw(" Page  "),
            Span::styled("[Esc]", theme::style_keybind()), Span::raw(" Back  "),
            Span::styled("[?]",   theme::style_keybind()), Span::raw(" Help"),
        ],
        ActiveView::Terminal => vec![
            Span::styled("[q]",    theme::style_keybind()), Span::raw(" Quit  "),
            Span::styled("[1-5]",  theme::style_keybind()), Span::raw(" Views  "),
            Span::styled("[Enter]",theme::style_keybind()), Span::raw(" Focus input  "),
            Span::styled("[↑/↓]",   theme::style_keybind()), Span::raw(" History  "),
            Span::styled("[Esc]",  theme::style_keybind()), Span::raw(" Blur  "),
            Span::styled("[x]",    theme::style_keybind()), Span::raw(" Kill job  "),
            Span::styled("[?]",    theme::style_keybind()), Span::raw(" Help"),
        ],
    };
    let line = Line::from(spans);
    let para = Paragraph::new(line).style(theme::style_dim());
    f.render_widget(para, area);
}

// ── Notification strip ────────────────────────────────────────────────────────

fn render_notifbar(f: &mut Frame, area: Rect, state: &AppState) {
    let (msg, style) = match &state.latest_notif {
        None => ("".to_string(), theme::style_dim()),
        Some(n) => {
            let pfx = match n.level {
                NotifLevel::Info    => "ℹ  ",
                NotifLevel::Success => "✓  ",
                NotifLevel::Warning => "⚠  ",
                NotifLevel::Error   => "✗  ",
            };
            let st = match n.level {
                NotifLevel::Info    => theme::style_accent(),
                NotifLevel::Success => theme::style_success(),
                NotifLevel::Warning => theme::style_warning(),
                NotifLevel::Error   => theme::style_error(),
            };
            (format!("{pfx}{}", n.message), st)
        }
    };
    f.render_widget(Paragraph::new(msg).style(style), area);
}

// ── Popup overlay ─────────────────────────────────────────────────────────────

fn render_popup(f: &mut Frame, area: Rect, popup: &PopupKind, _state: &AppState) {
    match popup {
        PopupKind::Help => {
            let rect = centre_rect(60, 20, area);
            f.render_widget(Clear, rect);
            let help = Paragraph::new(vec![
                Line::from(Span::styled("  FOUR-HUB — KEYBOARD REFERENCE", theme::style_title())),
                Line::raw(""),
                Line::from(vec![Span::styled("  F1-F5   ", theme::style_keybind()), Span::raw("Switch views")]),
                Line::from(vec![Span::styled("  ↑/↓/j/k ", theme::style_keybind()), Span::raw("Navigate lists")]),
                Line::from(vec![Span::styled("  Enter  ", theme::style_keybind()), Span::raw("Select / open inspector")]),
                Line::from(vec![Span::styled("  r      ", theme::style_keybind()), Span::raw("Run selected tool")]),
                Line::from(vec![Span::styled("  x      ", theme::style_keybind()), Span::raw("Kill selected job")]),
                Line::from(vec![Span::styled("  ^e     ", theme::style_keybind()), Span::raw("Export report")]),
                Line::from(vec![Span::styled("  ^f     ", theme::style_keybind()), Span::raw("Search")]),
                Line::from(vec![Span::styled("  Tab    ", theme::style_keybind()), Span::raw("Focus next panel  (Workspace: cycles hosts→ports→findings)")]),
                Line::from(vec![Span::styled("  w      ", theme::style_keybind()), Span::raw("Workflow menu")]),
                Line::from(vec![Span::styled("  S      ", theme::style_keybind()), Span::raw("Stealth ops menu")]),
                Line::from(vec![Span::styled("  Esc    ", theme::style_keybind()), Span::raw("Dismiss / cancel")]),
                Line::from(vec![Span::styled("  q      ", theme::style_keybind()), Span::raw("Quit")]),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_set(theme::BORDER_SET)
                    .border_style(theme::style_border_focused())
                    .title(Span::styled(" Help ", theme::style_title())),
            )
            .style(theme::style_popup());
            f.render_widget(help, rect);
        }

        PopupKind::Error { msg } => {
            let rect = centre_rect(50, 7, area);
            f.render_widget(Clear, rect);
            let para = Paragraph::new(msg.as_str())
                .wrap(Wrap { trim: true })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_error())
                        .title(Span::styled(" Error ", theme::style_error())),
                )
                .style(theme::style_popup());
            f.render_widget(para, rect);
        }

        PopupKind::ContextMenu { x, y, items } => {
            let w = 25_u16;
            let h = items.len() as u16 + 2;
            let rect = Rect::new(
                (*x).min(area.width.saturating_sub(w)),
                (*y).min(area.height.saturating_sub(h)),
                w, h,
            );
            f.render_widget(Clear, rect);
            let list_items: Vec<ListItem> = items
                .iter()
                .map(|i| ListItem::new(format!(" {}", i.label)))
                .collect();
            let list = List::new(list_items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_border_focused()),
                )
                .style(theme::style_popup())
                .highlight_style(theme::style_selected());
            f.render_widget(list, rect);
        }

        PopupKind::Confirm { msg, .. } => {
            let rect = centre_rect(52, 7, area);
            f.render_widget(Clear, rect);
            let para = Paragraph::new(format!("{msg}\n\n  [y] Confirm    [Esc] Cancel"))
                .wrap(Wrap { trim: true })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_warning())
                        .title(Span::styled(" Confirm ", theme::style_warning())),
                )
                .style(theme::style_popup());
            f.render_widget(para, rect);
        }

        PopupKind::TargetInput { query } => {
            let rect = centre_rect(58, 5, area);
            f.render_widget(Clear, rect);
            // Append a blinking-block cursor character so the user can see where they're typing.
            let display = format!("{query}█");
            let para = Paragraph::new(display.as_str())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_border_focused())
                        .title(Span::styled(
                            " ◆ SET TARGET  [Enter] Confirm   [Esc] Cancel   [Del] Clear ",
                            theme::style_title(),
                        )),
                )
                .style(theme::style_popup());
            f.render_widget(para, rect);
        }

        PopupKind::WorkflowMenu { names, selected } => {
            let h = (names.len() as u16 + 4).min(20);
            let rect = centre_rect(56, h, area);
            f.render_widget(Clear, rect);
            let items: Vec<ListItem> = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let style = if i == *selected { theme::style_selected() } else { theme::style_normal() };
                    ListItem::new(format!("  {n}")).style(style)
                })
                .collect();
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_border_focused())
                        .title(Span::styled(" ◆ Workflows  [Enter] Run  [↑/↓] Select  [Esc] Close ", theme::style_title())),
                )
                .style(theme::style_popup());
            f.render_widget(list, rect);
        }

        PopupKind::StealthMenu { selected } => {
            let ops = [
                "0  Forensic wipe (history + temp files)",
                "1  Randomise MAC — eth0",
                "2  Randomise MAC — wlan0",
                "3  Spoof process name → [kworker/0:1]",
            ];
            let h = ops.len() as u16 + 4;
            let rect = centre_rect(54, h, area);
            f.render_widget(Clear, rect);
            let items: Vec<ListItem> = ops
                .iter()
                .enumerate()
                .map(|(i, &op)| {
                    let style = if i == *selected { theme::style_selected() } else { theme::style_normal() };
                    ListItem::new(format!("  {op}")).style(style)
                })
                .collect();
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_set(theme::BORDER_SET)
                        .border_style(theme::style_border_focused())
                        .title(Span::styled(" ◆ Stealth Ops  [Enter] Execute  [↑/↓] Select  [Esc] Close ", theme::style_title())),
                )
                .style(theme::style_popup());
            f.render_widget(list, rect);
        }
    }
}
