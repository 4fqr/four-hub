
use ratatui::layout::{Constraint, Direction, Layout, Rect};
pub struct RootLayout {
    pub statusbar: Rect,
    pub content:   Rect,
    pub helpbar:   Rect,
    pub notifbar:  Rect,
}

impl RootLayout {
    pub fn compute(area: Rect) -> Self {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // status bar
                Constraint::Min(0),     // content
                Constraint::Length(1),  // notification strip
                Constraint::Length(1),  // help bar
            ])
            .split(area);
        Self {
            statusbar: chunks[0],
            content:   chunks[1],
            notifbar:  chunks[2],
            helpbar:   chunks[3],
        }
    }
}
pub struct DashboardLayout {
    pub stats:    Rect,
    pub jobs:     Rect,
    pub findings: Rect,
    pub chart:    Rect,
}

impl DashboardLayout {
    pub fn compute(area: Rect) -> Self {
        let h = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(0)])
            .split(area);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(h[1]);
        let right_bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(right[1]);
        Self {
            stats:    h[0],
            jobs:     right[0],
            findings: right_bottom[0],
            chart:    right_bottom[1],
        }
    }
}
pub struct LauncherLayout {
    pub categories: Rect,
    pub tools:      Rect,
    pub detail:     Rect,
}

impl LauncherLayout {
    pub fn compute(area: Rect) -> Self {
        let h = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(22), Constraint::Min(0)])
            .split(area);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(10)])
            .split(h[1]);
        Self {
            categories: h[0],
            tools:      right[0],
            detail:     right[1],
        }
    }
}
pub struct WorkspaceLayout {
    pub hosts:    Rect,
    pub ports:    Rect,
    pub findings: Rect,
}

impl WorkspaceLayout {
    pub fn compute(area: Rect) -> Self {
        let h = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(h[1]);
        Self { hosts: h[0], ports: right[0], findings: right[1] }
    }
}
pub struct InspectorLayout {
    pub header:   Rect,
    pub body:     Rect,
    pub evidence: Rect,
}

impl InspectorLayout {
    pub fn compute(area: Rect) -> Self {
        let v = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Min(0),
                Constraint::Percentage(30),
            ])
            .split(area);
        Self { header: v[0], body: v[1], evidence: v[2] }
    }
}
pub fn centre_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x.saturating_add(area.width.saturating_sub(width) / 2);
    let y = area.y.saturating_add(area.height.saturating_sub(height) / 2);
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
