// ─── Four-Hub · tui/app_state.rs ─────────────────────────────────────────────
//! Central UI state – every widget reads from this struct.

use crate::{
    config::AppConfig,
    db::{Database, DbStats, Finding, Host, Port},
    tools::{executor::ToolExecutor, spec::ToolSpec},
};
use chrono::{DateTime, Utc};
use crossterm::event::KeyEvent;
// (parking_lot::RwLock removed — interior mutability not needed here)
use std::collections::HashMap;
use std::sync::Arc;

// ── Active view ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveView {
    Dashboard,
    ToolLauncher,
    Workspace,
    Inspector,
    Terminal,
}

impl ActiveView {
    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard    => "DASHBOARD",
            Self::ToolLauncher => "LAUNCHER",
            Self::Workspace    => "WORKSPACE",
            Self::Inspector    => "INSPECTOR",
            Self::Terminal     => "TERMINAL",
        }
    }
}

// ── Notification ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifLevel { Info, Success, Warning, Error }

#[derive(Debug, Clone)]
pub struct Notification {
    pub level:   NotifLevel,
    pub message: String,
    pub at:      DateTime<Utc>,
}

// ── Running job ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct RunningJob {
    pub id:       String,
    pub tool:     String,
    pub target:   String,
    pub started:  DateTime<Utc>,
    pub finished: bool,
    pub exit_code: Option<i32>,
    pub output:   Vec<String>,
}

// ── Panel focus ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel { Left, Right, Top, Bottom }

// ── AppState ──────────────────────────────────────────────────────────────────
pub struct AppState {
    pub cfg:           AppConfig,
    pub db:            Arc<Database>,
    pub active_view:   ActiveView,
    pub panel:         Panel,
    pub term_width:    u16,
    pub term_height:   u16,

    // ── Data caches (refreshed on Tick) ──────────────────────────────────────
    pub db_stats:      DbStats,
    pub hosts:         Vec<Host>,
    pub selected_host: Option<usize>,
    pub ports:         Vec<Port>,
    pub selected_port: Option<usize>,
    pub findings:      Vec<Finding>,
    pub selected_finding: Option<usize>,

    // ── Tool launcher state ───────────────────────────────────────────────────
    /// Full map category → tools populated from the registry at startup.
    pub all_tools:          HashMap<String, Vec<ToolSpec>>,
    pub tool_categories:    Vec<String>,
    pub selected_category:  usize,
    pub tools_in_category:  Vec<ToolSpec>,
    pub selected_tool:      usize,
    pub tool_target_input:  String,
    pub current_target:     String,

    // ── Running jobs ─────────────────────────────────────────────────────────
    pub jobs:          Vec<RunningJob>,
    pub selected_job:  Option<usize>,

    // ── Notifications ─────────────────────────────────────────────────────────
    pub notifications: Vec<Notification>,
    pub latest_notif:  Option<Notification>,

    // ── Popup / modal ─────────────────────────────────────────────────────────
    pub popup:         Option<PopupKind>,

    // ── Embedded terminal widget ──────────────────────────────────────────────
    pub terminal:      EmbeddedTermState,

    // ── Inspector ────────────────────────────────────────────────────────────
    pub inspector_finding: Option<Finding>,
    pub inspector_scroll:  u16,

    // ── Search ────────────────────────────────────────────────────────────────
    pub search_query:  String,
    pub search_active: bool,

    // ── Scroll offsets ────────────────────────────────────────────────────────
    pub scroll_offset: usize,

    // ── Drag split state ──────────────────────────────────────────────────────
    pub split_x:       u16,

    // ── Pending terminal command (set by key handler, consumed by run loop) ───
    pub pending_terminal_cmd: Option<String>,
}

#[derive(Debug, Clone)]
pub enum PopupKind {
    Help,
    TargetInput { query: String },
    Confirm { msg: String, action: ConfirmAction },
    ContextMenu { x: u16, y: u16, items: Vec<ContextItem> },
    Error { msg: String },
    WorkflowMenu { names: Vec<String>, selected: usize },
    StealthMenu { selected: usize },
}

#[derive(Debug, Clone)]
pub enum ConfirmAction { KillJob(String), DeleteFinding(String), ExportReport, RunWorkflow(String), StealthOp(u8) }

#[derive(Debug, Clone)]
pub struct ContextItem {
    pub label:  String,
    pub action: ContextAction,
}

#[derive(Debug, Clone)]
pub enum ContextAction {
    LaunchTool(ToolSpec),
    CopyText(String),
    OpenInspector,
}

// ── Embedded terminal ─────────────────────────────────────────────────────────
#[derive(Debug, Default)]
pub struct EmbeddedTermState {
    pub lines:    Vec<String>,
    pub focused:  bool,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub input:    String,
    pub history:  Vec<String>,
    pub hist_pos: usize,
}

impl AppState {
    pub fn new(cfg: AppConfig, db: Arc<Database>) -> Self {
        Self {
            cfg,
            db,
            active_view:       ActiveView::Dashboard,
            panel:             Panel::Left,
            term_width:        80,
            term_height:       24,
            db_stats:          DbStats::default(),
            hosts:             Vec::new(),
            selected_host:     None,
            ports:             Vec::new(),
            selected_port:     None,
            findings:          Vec::new(),
            selected_finding:  None,
            all_tools:         HashMap::new(),
            tool_categories:   Vec::new(),
            selected_category: 0,
            tools_in_category: Vec::new(),
            selected_tool:     0,
            tool_target_input: String::new(),
            current_target:    String::new(),
            jobs:              Vec::new(),
            selected_job:      None,
            notifications:     Vec::new(),
            latest_notif:      None,
            popup:             None,
            terminal:          EmbeddedTermState::default(),
            inspector_finding: None,
            inspector_scroll:  0,
            search_query:      String::new(),
            search_active:     false,
            scroll_offset:          0,
            split_x:               40,
            pending_terminal_cmd:  None,
        }
    }

    // ── View ──────────────────────────────────────────────────────────────────

    pub fn set_view(&mut self, v: ActiveView) {
        self.active_view   = v;
        self.scroll_offset = 0;
    }

    pub fn active_view(&self) -> ActiveView { self.active_view }

    // ── Terminal size ─────────────────────────────────────────────────────────

    pub fn resize(&mut self, w: u16, h: u16) {
        self.term_width  = w;
        self.term_height = h;
    }

    // ── Stats refresh (called on Tick) ────────────────────────────────────────

    pub async fn update_stats(&mut self, db: &Database) {
        if let Ok(s) = db.stats() { self.db_stats = s; }
        if let Ok(h) = db.all_hosts() { self.hosts = h; }
        if let Ok(f) = db.all_findings() { self.findings = f; }
        // Load ports for the selected host.
        if let Some(idx) = self.selected_host {
            if let Some(host) = self.hosts.get(idx) {
                let hid = host.id.clone();
                if let Ok(p) = db.ports_for_host(&hid) {
                    self.ports = p;
                }
            }
        } else {
            self.ports.clear();
        }
    }

    // ── Notifications ─────────────────────────────────────────────────────────

    pub fn push_notification(&mut self, level: NotifLevel, message: String) {
        let n = Notification { level, message: message.clone(), at: Utc::now() };
        self.latest_notif = Some(n.clone());
        self.notifications.push(n);
        if self.notifications.len() > 200 {
            self.notifications.remove(0);
        }
    }

    // ── Jobs ──────────────────────────────────────────────────────────────────

    pub fn register_job(&mut self, job_id: String, tool_name: String) {
        self.jobs.push(RunningJob {
            id:        job_id,
            tool:      tool_name,
            target:    self.current_target.clone(),
            started:   Utc::now(),
            finished:  false,
            exit_code: None,
            output:    Vec::new(),
        });
    }

    pub fn append_tool_output(&mut self, job_id: &str, line: String) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == job_id) {
            job.output.push(line);
            if job.output.len() > 5000 {
                job.output.remove(0);
            }
        }
    }

    pub fn mark_tool_finished(&mut self, job_id: &str, exit_code: i32) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == job_id) {
            job.finished  = true;
            job.exit_code = Some(exit_code);
        }
    }

    pub async fn kill_selected_job(&mut self, executor: &Arc<ToolExecutor>) {
        if let Some(idx) = self.selected_job {
            if let Some(job) = self.jobs.get(idx) {
                let _ = executor.kill(&job.id).await;
            }
        }
    }

    // ── Findings ──────────────────────────────────────────────────────────────

    pub fn push_finding(&mut self, f: Finding) {
        self.findings.insert(0, f);
        if self.findings.len() > 10_000 {
            self.findings.truncate(10_000);
        }
    }

    pub fn open_inspector_for_selected(&mut self) {
        if let Some(idx) = self.selected_finding {
            if let Some(f) = self.findings.get(idx) {
                self.inspector_finding = Some(f.clone());
                self.active_view       = ActiveView::Inspector;
                self.inspector_scroll  = 0;
            }
        }
    }

    // ── Tool launcher ─────────────────────────────────────────────────────────

    pub fn selected_tool_spec(&self) -> Option<&ToolSpec> {
        self.tools_in_category.get(self.selected_tool)
    }

    pub fn current_target(&self) -> &String { &self.current_target }

    pub fn project_name(&self) -> String { self.cfg.general.project_name.clone() }

    // ── Category navigation (Launcher view) ───────────────────────────────────

    pub fn set_category_idx(&mut self, idx: usize) {
        if idx < self.tool_categories.len() {
            self.selected_category  = idx;
            let cat = self.tool_categories[idx].clone();
            self.tools_in_category  = self.all_tools.get(&cat).cloned().unwrap_or_default();
            self.selected_tool      = 0;
        }
    }

    pub fn prev_category(&mut self) {
        if self.tool_categories.is_empty() { return; }
        let idx = if self.selected_category == 0 {
            self.tool_categories.len() - 1
        } else {
            self.selected_category - 1
        };
        self.set_category_idx(idx);
    }

    pub fn next_category(&mut self) {
        if self.tool_categories.is_empty() { return; }
        let idx = (self.selected_category + 1) % self.tool_categories.len();
        self.set_category_idx(idx);
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    pub fn select_prev(&mut self) {
        match self.active_view {
            ActiveView::ToolLauncher => {
                if self.selected_tool > 0 { self.selected_tool -= 1; }
            }
            ActiveView::Workspace => {
                if let Some(ref mut i) = self.selected_host { if *i > 0 { *i -= 1; } }
                else if !self.hosts.is_empty() { self.selected_host = Some(0); }
            }
            ActiveView::Dashboard => {
                if let Some(ref mut i) = self.selected_job { if *i > 0 { *i -= 1; } }
            }
            ActiveView::Inspector => {
                self.inspector_scroll = self.inspector_scroll.saturating_sub(1);
            }
            _ => { if self.scroll_offset > 0 { self.scroll_offset -= 1; } }
        }
    }

    pub fn select_next(&mut self) {
        match self.active_view {
            ActiveView::ToolLauncher => {
                let max = self.tools_in_category.len().saturating_sub(1);
                if self.selected_tool < max { self.selected_tool += 1; }
            }
            ActiveView::Workspace => {
                let max = self.hosts.len().saturating_sub(1);
                match &mut self.selected_host {
                    Some(i) if *i < max => { *i += 1; }
                    None if !self.hosts.is_empty() => { self.selected_host = Some(0); }
                    _ => {}
                }
            }
            ActiveView::Dashboard => {
                let max = self.jobs.len().saturating_sub(1);
                match &mut self.selected_job {
                    Some(i) if *i < max => { *i += 1; }
                    None if !self.jobs.is_empty() => { self.selected_job = Some(0); }
                    _ => {}
                }
            }
            ActiveView::Inspector => { self.inspector_scroll += 1; }
            _ => { self.scroll_offset += 1; }
        }
    }

    pub fn next_panel(&mut self) {
        self.panel = match self.panel {
            Panel::Left   => Panel::Right,
            Panel::Right  => Panel::Top,
            Panel::Top    => Panel::Bottom,
            Panel::Bottom => Panel::Left,
        };
    }

    pub fn page_up(&mut self) {
        let step = (self.term_height / 2) as usize;
        self.scroll_offset = self.scroll_offset.saturating_sub(step);
    }

    pub fn page_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add((self.term_height / 2) as usize);
    }

    pub fn scroll_up(&mut self)     { if self.scroll_offset > 0 { self.scroll_offset -= 1; } }
    pub fn scroll_down(&mut self)   { self.scroll_offset += 1; }
    pub fn scroll_top(&mut self)    { self.scroll_offset = 0; }
    pub fn scroll_bottom(&mut self) { self.scroll_offset = usize::MAX / 2; }

    // ── Click / drag ─────────────────────────────────────────────────────────

    pub fn click(&mut self, col: u16, row: u16) {
        const STATUSBAR_H: u16 = 3;

        // ── Tab bar ───────────────────────────────────────────────────────────
        if row < STATUSBAR_H {
            let w = (self.term_width / 5).max(1);
            self.active_view = match (col / w).min(4) {
                0 => ActiveView::Dashboard,
                1 => ActiveView::ToolLauncher,
                2 => ActiveView::Workspace,
                3 => ActiveView::Inspector,
                4 => ActiveView::Terminal,
                _ => self.active_view,
            };
            return;
        }

        // ── Content area ──────────────────────────────────────────────────────
        let content_row = row.saturating_sub(STATUSBAR_H);

        match self.active_view {
            ActiveView::ToolLauncher => {
                const CAT_W: u16 = 22;
                if col < CAT_W {
                    let item = content_row.saturating_sub(1) as usize;
                    if item < self.tool_categories.len() {
                        self.set_category_idx(item);
                    }
                } else {
                    let item = content_row.saturating_sub(1) as usize;
                    if item < self.tools_in_category.len() {
                        self.selected_tool = item;
                    }
                }
            }
            ActiveView::Workspace => {
                let host_w = (self.term_width * 30 / 100).max(1);
                if col < host_w {
                    let item = content_row.saturating_sub(2) as usize;
                    if item < self.hosts.len() { self.selected_host = Some(item); }
                } else {
                    let mid = self.term_height.saturating_sub(STATUSBAR_H) / 2;
                    if content_row < mid {
                        let item = content_row.saturating_sub(2) as usize;
                        if item < self.ports.len() { self.selected_port = Some(item); }
                    } else {
                        let item = content_row.saturating_sub(mid + 2) as usize;
                        if item < self.findings.len() { self.selected_finding = Some(item); }
                    }
                }
            }
            ActiveView::Dashboard => {
                let left_w: u16 = 30;
                if col >= left_w {
                    let item = content_row.saturating_sub(2) as usize;
                    if !self.jobs.is_empty() && item < self.jobs.len() {
                        self.selected_job = Some(item);
                    }
                }
            }
            ActiveView::Terminal => {
                self.terminal.focused = true;
            }
            _ => {}
        }
    }

    pub fn context_menu(&mut self, x: u16, y: u16) {
        self.popup = Some(PopupKind::ContextMenu {
            x, y,
            items: vec![
                ContextItem { label: "Inspect".into(), action: ContextAction::OpenInspector },
            ],
        });
    }

    pub fn drag(&mut self, col: u16, _row: u16) {
        self.split_x = col;
    }

    // ── Popups ────────────────────────────────────────────────────────────────

    pub fn dismiss_popup(&mut self) { self.popup = None; }

    // ── Search ────────────────────────────────────────────────────────────────

    pub fn open_search(&mut self) {
        self.search_active = true;
        self.search_query.clear();
    }

    // ── Embedded terminal ─────────────────────────────────────────────────────

    pub fn terminal_focused(&self) -> bool {
        self.active_view == ActiveView::Terminal && self.terminal.focused
    }

    pub fn terminal_input(&mut self, key: KeyEvent) -> Option<String> {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Char(c) => { self.terminal.input.push(c); None }
            KeyCode::Backspace => { self.terminal.input.pop(); None }
            KeyCode::Enter => {
                let cmd = self.terminal.input.drain(..).collect::<String>();
                if cmd.is_empty() { return None; }
                self.terminal.history.push(cmd.clone());
                self.terminal.hist_pos = self.terminal.history.len();
                self.push_terminal_line(format!("$ {cmd}"));
                Some(cmd)  // caller will execute this
            }
            KeyCode::Up => {
                if self.terminal.hist_pos > 0 {
                    self.terminal.hist_pos -= 1;
                    if let Some(h) = self.terminal.history.get(self.terminal.hist_pos) {
                        self.terminal.input = h.clone();
                    }
                }
                None
            }
            KeyCode::Down => {
                self.terminal.hist_pos =
                    (self.terminal.hist_pos + 1).min(self.terminal.history.len());
                if self.terminal.hist_pos == self.terminal.history.len() {
                    self.terminal.input.clear();
                } else if let Some(h) = self.terminal.history.get(self.terminal.hist_pos) {
                    self.terminal.input = h.clone();
                }
                None
            }
            _ => None
        }
    }

    pub fn blur_terminal(&mut self) {
        self.terminal.focused = false;
    }

    pub fn push_terminal_line(&mut self, line: String) {
        self.terminal.lines.push(line);
        if self.terminal.lines.len() > 10_000 {
            self.terminal.lines.remove(0);
        }
    }
}
